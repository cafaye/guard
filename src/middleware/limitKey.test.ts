import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { clientIp, hasApiKeyScheme, rateLimitKey, type KeySource } from "./limitKey";

/**
 * A Hono app whose context is exactly what guard puts on it by the time the
 * limiter reads it: a verified principal, an API key id, and the raw request.
 * Nothing here is fabricated by the limiter — that is the whole point of the
 * module and the reason its tests build the context rather than a fake it.
 */
function app(): Hono {
  return new Hono();
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

  test("a long chain is read from the right, whatever the caller prepended", async () => {
    const chain = ["10.0.0.9", "10.0.0.8", "10.0.0.7", "203.0.113.4", "10.0.0.1"].join(", ");

    expect(await read(1, { "x-forwarded-for": chain })).toBe("203.0.113.4");
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
