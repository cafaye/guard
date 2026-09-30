import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import {
  clientIp,
  hasApiKeyScheme,
  rateLimitKey,
  type KeySource,
  type KeyVariables,
} from "./limitKey";

/**
 * A Hono app whose context is exactly what guard puts on it by the time the
 * limiter reads it: a verified principal, an API key id, and the raw request.
 * Nothing here is fabricated by the limiter — that is the whole point of the
 * module and the reason its tests build the context rather than a fake it.
 */
function app(): Hono<{ Variables: KeyVariables }> {
  const a = new Hono<{ Variables: KeyVariables }>();
  // Hono's default error handler turns a thrown RangeError into a 500, which
  // would hide the one thing this file wants to see: that a bad trusted-proxy
  // count is refused rather than tolerated.
  a.onError((error) => {
    throw error;
  });
  return a;
}

describe("the key priority table", () => {
  const cases: Array<{ what: string; given: KeySource; key: string }> = [
    {
      what: "an account claim beats an API key id and the address",
      given: { accountId: "acc-42", apiKeyId: "key-7", address: "203.0.113.4" },
      key: "account:acc-42",
    },
    {
      what: "without an account claim the verified subject stands in for the account",
      given: { accountId: "3f2504e0-4f89-41d3-9a0c-0305e82c3301", apiKeyId: "key-7", address: "203.0.113.4" },
      key: "account:3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    },
    {
      what: "an API key id beats the address when there is no verified account",
      given: { accountId: null, apiKeyId: "key-7", address: "203.0.113.4" },
      key: "apikey:key-7",
    },
    {
      what: "the address is the last resort",
      given: { accountId: null, apiKeyId: null, address: "203.0.113.4" },
      key: "ip:203.0.113.4",
    },
    {
      what: "an empty claim is no claim",
      given: { accountId: "", apiKeyId: "key-7", address: "203.0.113.4" },
      key: "apikey:key-7",
    },
    {
      what: "an empty key id is no key",
      given: { accountId: null, apiKeyId: "", address: "203.0.113.4" },
      key: "ip:203.0.113.4",
    },
    {
      what: "with nothing at all the bucket is a named unknown, not a blank",
      given: { accountId: null, apiKeyId: null, address: "" },
      key: "ip:unknown",
    },
  ];

  for (const { what, given, key } of cases) {
    test(what, () => {
      expect(rateLimitKey(given)).toBe(key);
    });
  }

  test("the account id comes from the verified principal, never from a header", async () => {
    const seen: string[] = [];
    const a = app();
    a.use("*", async (c, next) => {
      seen.push(
        rateLimitKey({
          accountId: c.get("principal")?.accountId ?? null,
          apiKeyId: c.get("apiKeyId") ?? null,
          address: clientIp(c, 0),
        }),
      );
      await next();
    });
    a.get("/", (c) => c.json({ ok: true }));

    // A caller who names an account in headers they chose gets nothing from them.
    await a.request("/", { headers: { "x-account-id": "acc-attacker", "x-forwarded-for": "198.51.100.9" } });

    expect(seen).toEqual(["ip:unknown"]);
  });
});

describe("clientIp and the trusted proxy count", () => {
  const read = async (trustedProxies: number, headers: Record<string, string>): Promise<string> => {
    let key = "";
    const a = app();
    a.use("*", async (c, next) => {
      key = clientIp(c, trustedProxies);
      await next();
    });
    a.get("/", (c) => c.json({ ok: true }));
    await a.request("/", { headers });
    return key;
  };

  test("with no trusted proxies the forwarding header is ignored entirely", async () => {
    // The header is one the caller chose. Trusting it would mean every caller
    // could mint a fresh allowance per request, which is a self-DoS dressed as
    // a limiter.
    expect(await read(0, { "x-forwarded-for": "203.0.113.4" })).toBe("unknown");
  });

  test("with one trusted proxy the client's own entry is taken", async () => {
    expect(await read(1, { "x-forwarded-for": "203.0.113.4" })).toBe("203.0.113.4");
  });

  test("with two trusted proxies the entry the second one appended is taken", async () => {
    expect(await read(2, { "x-forwarded-for": "203.0.113.4, 10.0.0.1" })).toBe("203.0.113.4");
  });

  test("entries a caller prepended to the chain are ignored", async () => {
    // The operator says two proxies appended. Anything to the left of that is
    // whatever the caller felt like sending, so the address is read from the
    // right — the only direction that can be wrong in the safe way.
    expect(await read(2, { "x-forwarded-for": "198.51.100.9, 203.0.113.4, 10.0.0.1" })).toBe("203.0.113.4");
  });

  test("a chain no longer than the trusted count falls back to the peer", async () => {
    // Fewer entries than proxies means the peer address is the only candidate.
    // There is no socket address to read under `app.request()`, so this is the
    // shared bucket — which groups more callers than necessary and never trusts
    // one, which is the direction to be wrong in.
    expect(await read(3, { "x-forwarded-for": "203.0.113.4" })).toBe("unknown");
    expect(await read(1, {})).toBe("unknown");
  });

  test("malformed entries are not accepted as addresses", async () => {
    expect(await read(1, { "x-forwarded-for": "  " })).toBe("unknown");
    expect(await read(1, { "x-forwarded-for": "unknown" })).toBe("unknown");
    // A blank middle entry is skipped rather than becoming a bucket of its own.
    expect(await read(1, { "x-forwarded-for": "203.0.113.4, , 10.0.0.1" })).toBe("10.0.0.1");
  });

  test("an entry that is not an address is not accepted as one either", async () => {
    // The three cases the existing filter *does* catch — whitespace, the literal
    // word `unknown`, a blank hop — are all rejected by an explicit test or an
    // emptiness check. What is left is the positive filter itself, and it is
    // looser than the comment above it claims:
    //
    //     Only something shaped like an IP literal is accepted
    //
    // `[0-9a-f:.%]+` is not that. `deadbeef` is a hex word, not a host; `..` and
    // `::` are not an address either. All three pass, and each one that passes
    // becomes a bucket identity, so a caller who can put an entry in the trusted
    // position mints an unlimited number of allowances by varying a string that
    // is not an address at all. The rejection that stops this has to be "is this
    // an address", not "does this contain no spaces".
    expect(await read(1, { "x-forwarded-for": "deadbeef" })).toBe("unknown");
    expect(await read(1, { "x-forwarded-for": "abcd" })).toBe("unknown");
    expect(await read(1, { "x-forwarded-for": "..." })).toBe("unknown");
    // Octets out of range and short forms are the shape a caller reaches for
    // when they are trying to look like an address without being one.
    expect(await read(1, { "x-forwarded-for": "999.1.1.1" })).toBe("unknown");
    expect(await read(1, { "x-forwarded-for": "1.2.3" })).toBe("unknown");
    expect(await read(1, { "x-forwarded-for": "203.0.113.4, deadbeef" })).toBe("unknown");
  });

  test("real addresses in every shape the header carries are still read", async () => {
    // The filter above is a rejection list of what is not an address. This is the
    // other half of the same contract: tightening it must not refuse the forms a
    // real proxy emits, or the fix is a limiter keyed on nothing.
    expect(await read(1, { "x-forwarded-for": "203.0.113.4" })).toBe("203.0.113.4");
    expect(await read(1, { "x-forwarded-for": "203.0.113.4:44321" })).toBe("203.0.113.4");
    expect(await read(1, { "x-forwarded-for": "2001:db8::1" })).toBe("2001:db8::1");
    expect(await read(1, { "x-forwarded-for": "[2001:db8::1]:44321" })).toBe("2001:db8::1");
    expect(await read(1, { "x-forwarded-for": "10.0.0.1" })).toBe("10.0.0.1");
    // `::` and `::1` are legitimately-shaped IPv6 literals, so a fix that
    // rejected them would be refusing real addresses to stop a spoof.
    expect(await read(1, { "x-forwarded-for": "::1" })).toBe("::1");
    // The zone suffix is part of an IPv6 literal and used to be why the filter
    // had to tolerate `%`.
    expect(await read(1, { "x-forwarded-for": "fe80::1%eth0" })).toBe("fe80::1%eth0");
  });

  test("a long chain is read from the right, and nothing a caller prepends is ever read", async () => {
    // One trusted proxy means one hop: the rightmost entry is what that proxy
    // saw, so it is the caller's address and every entry to its left is
    // something the caller wrote. A caller who prepends a fresh address per
    // request therefore does not get a fresh bucket — the answer does not move
    // off the right, it just slides left past the junk.
    const chain = ["10.0.0.9", "10.0.0.8", "10.0.0.7", "203.0.113.4", "10.0.0.1"].join(", ");

    expect(await read(1, { "x-forwarded-for": chain })).toBe("10.0.0.1");
    expect(await read(1, { "x-forwarded-for": `198.51.100.7, ${chain}` })).toBe("10.0.0.1");
    // Two proxies read one further in, which is the same rule at a different hop
    // count rather than a second rule.
    expect(await read(2, { "x-forwarded-for": chain })).toBe("203.0.113.4");
  });

  test("refuses a negative trusted proxy count", async () => {
    await expect(read(-1, { "x-forwarded-for": "203.0.113.4" })).rejects.toThrow(RangeError);
  });
});

describe("recognising an API key credential", () => {
  const scheme = async (authorization: string | null): Promise<boolean> => {
    const a = app();
    let seen = false;
    a.use("*", async (c, next) => {
      seen = hasApiKeyScheme(c);
      await next();
    });
    a.get("/", (c) => c.json({ ok: true }));

    await a.request("/", { headers: authorization === null ? {} : { authorization } });
    return seen;
  };

  test("recognises the ApiKey scheme", async () => {
    expect(await scheme("ApiKey caf_secret")).toBe(true);
  });

  test("is case-insensitive on the scheme, as HTTP auth schemes are", async () => {
    expect(await scheme("apikey caf_secret")).toBe(true);
  });

  test("leaves a bearer token for the JWT verifier", async () => {
    expect(await scheme("Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.x")).toBe(false);
  });

  test("leaves a request with no credential at all", async () => {
    expect(await scheme(null)).toBe(false);
    expect(await scheme("")).toBe(false);
  });
});
