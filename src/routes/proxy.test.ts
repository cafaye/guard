// The pass-through, held to what it promises.
//
// Two halves, and the order is the argument:
//
//   1. WHAT GOES OUT. Where the request goes, which of the caller's headers
//      cross, and — the security content of the routing packet — that the
//      credential reaching a service is guard's own and never the caller's.
//   2. WHAT COMES BACK. That a failure from behind the edge is translated, and
//      that nothing about the service's address, version or stack reaches the
//      caller.
//
// Nothing here opens a socket: the upstream is an injected `fetch` that records
// what it was handed. That is the same seam `bff/auth.ts` uses and for the same
// reason — the claims are about what guard *sends*, and a listening server would
// only add the network's opinions to both sides.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { createApp } from "../index";
import { createRouteProxy, upstreamPath } from "./proxy";
import { routeTable, type RouteTable } from "./table";
import { SESSION_COOKIE } from "../bff/auth";
import { signToken, startJwksServer, testKey, type JwksServer, type TestKey } from "../../test/jwksServer";

const AUDIENCE = "guard-test";
const ACCOUNT = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

/** One service, with the credential a deployment would configure for it. */
const TABLE: RouteTable = {
  "/v1/pantry": { baseUrl: "http://pantry.test:8080", token: "svc-pantry-token" },
  "/v1/quiet": { baseUrl: "http://quiet.test:8080" },
};

/** What the upstream was actually handed, read off the request it received. */
type Recorded = {
  url: string;
  method: string;
  headers: Headers;
  body: string;
};

/**
 * A `Request` out of whatever the proxy handed the double, so the recorder sees
 * the same object a real service would. The coercion is the one
 * `test/fakeIdentity.ts` already does, for the same reason: `fetch` accepts
 * three input shapes and the recorder should not care which one arrived.
 */
function toRequest(input: string | URL | Request, init?: RequestInit): Request {
  if (input instanceof Request) return init === undefined ? input : new Request(input, init);

  return new Request(typeof input === "string" ? input : input.href, init);
}

function recorder() {
  const calls: Recorded[] = [];
  let reply: (request: Request) => Response | Promise<Response> = () => Response.json({ ok: true });

  return {
    calls,
    answerWith(respond: (request: Request) => Response | Promise<Response>) {
      reply = respond;
    },
    fetch: async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const request = toRequest(input, init);
      calls.push({
        url: request.url,
        method: request.method,
        headers: new Headers(request.headers),
        body: await request.clone().text(),
      });
      return reply(request);
    },
  };
}

/**
 * The gateway with routing on and an upstream double.
 *
 * The `jwt` option is always on, because that is the shape a deployment runs in
 * and because most of what is asserted below is only true *underneath* the token
 * gate: an app built with no verifier serves the pass-through to anyone, which is
 * correct (there is no token to check) and useless as a fixture.
 */
function gateway(table: RouteTable, upstream: ReturnType<typeof recorder>) {
  return createApp({
    routes: table,
    proxy: { fetch: upstream.fetch },
    jwt: { issuer: identity.issuer, audience: AUDIENCE },
  });
}

let identity: JwksServer;
let key: TestKey;

beforeAll(async () => {
  // A key pair generated in this process for this file, and a JWKS host to serve
  // it from. It is not a key from anywhere: nothing in this repository may hold a
  // signing key that is not minted on the spot and never written down.
  key = await testKey("proxy-key");
  identity = await startJwksServer(key);
});

afterAll(() => identity.stop());

const token = async (): Promise<string> => {
  const seconds = (offset = 0) => Math.floor(Date.now() / 1000) + offset;

  return signToken(key, {
    iss: identity.issuer,
    aud: AUDIENCE,
    sub: ACCOUNT,
    account_id: ACCOUNT,
    iat: seconds(),
    exp: seconds(60),
    scope: "profile.read",
  });
};

// ------------------------------------------------------------ what goes out

describe("the destination is configuration, never the request", () => {
  let upstream: ReturnType<typeof recorder>;

  beforeEach(() => {
    upstream = recorder();
  });
  test("a routed path reaches its service with the prefix removed", async () => {
    const res = await gateway(TABLE, upstream).request("/v1/pantry/items?limit=2", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(200);
    // The one target: the configured origin plus the rebuilt path. No host, no
    // port and no prefix out of the caller's request, and the query the caller
    // wrote is carried because it is the caller's own question to that service.
    expect(upstream.calls[0]?.url).toBe("http://pantry.test:8080/items?limit=2");
  });

  test("the prefix itself is a request, and reaches the service's root", async () => {
    await gateway(TABLE, upstream).request("/v1/pantry", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(upstream.calls[0]?.url).toBe("http://pantry.test:8080/");
  });

  test("no header a caller writes can move the target", async () => {
    // The shape `edge.test.ts` already pins for identity's calls, asked again
    // of the one call that is new. Every header below has been used to redirect
    // a proxy somewhere else.
    await gateway(TABLE, upstream).request("/v1/pantry/items", {
      headers: {
        authorization: `Bearer ${await token()}`,
        host: "169.254.169.254",
        "x-forwarded-host": "169.254.169.254",
        "x-original-url": "http://169.254.169.254/latest/meta-data/",
        "x-rewrite-url": "http://127.0.0.1:6379/",
        "x-pantry-url": "http://metadata.test/",
        referer: "http://169.254.169.254/",
      },
    });

    expect(upstream.calls).toHaveLength(1);
    expect(upstream.calls[0]?.url).toBe("http://pantry.test:8080/items");
  });

  test("a path nothing claims is guard's own 404, and no service is contacted", async () => {
    const app = gateway(TABLE, upstream);

    for (const path of ["/v1/unknown", "/v1/pantryx/items", "/v1alpha/items", "/v1"]) {
      const res = await app.request(path, { headers: { authorization: `Bearer ${await token()}` } });

      expect(`${path} -> ${res.status}`).toContain("-> 404");
    }
    expect(upstream.calls).toHaveLength(0);
  });

  test("a traversal cannot reach a service the table did not route", async () => {
    // Two halves, because the defence is two halves.
    //
    // WHATWG URL parsing resolves `.`, `..` and their percent-encoded spellings
    // (`%2e%2e`) *before* guard sees the path, so `..` cannot survive to be
    // concatenated into an upstream URL. What it can do is climb — and climbing
    // out of the API surface reaches nothing at all, because the mount is
    // `/v1/*` and there is no table entry for `/admin`.
    //
    // The spellings that DO survive the parser are the ones guard refuses: a
    // doubled slash, an encoded separator and a broken escape are not paths it
    // will rebuild, and each is a 404 with no service contacted.
    const app = gateway({ ...TABLE, "/v1/billing": { baseUrl: "http://billing.test" } }, upstream);

    for (const path of [
      "/v1/pantry/%2E%2E/%2E%2E/admin",
      "/v1/pantry/../../../admin",
      "/v1/pantry//items",
      "/v1/pantry/a%2fb",
      "/v1/pantry/..%2fadmin",
      "/v1/pantry/%",
    ]) {
      const res = await app.request(path, { headers: { authorization: `Bearer ${await token()}` } });

      expect(`${path} -> ${res.status}`).toContain("-> 404");
    }
    expect(upstream.calls).toHaveLength(0);
  });

  test("climbing to a prefix that IS routed reaches that service and not the one below", async () => {
    // The complement, and the reason the case above is a control rather than a
    // blanket refusal: `%2e%2e` is `..` to the URL parser, so this resolves to
    // `/v1/billing/items` and is served by the entry that claims it. The claim is
    // that the *table* decides, not that guard refuses everything with a dot in
    // it — a proxy that refused those would be a proxy nobody could route with.
    const app = gateway({ ...TABLE, "/v1/billing": { baseUrl: "http://billing.test" } }, upstream);

    const res = await app.request("/v1/pantry/%2e%2e/billing/items", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(200);
    expect(upstream.calls).toHaveLength(1);
    expect(upstream.calls[0]?.url).toBe("http://billing.test/items");
  });

  test("a double-encoded dot segment is forwarded as a literal name, re-encoded", async () => {
    // `%252e%252e` decodes once to `%2e%2e` — a name, not a segment — and is
    // re-encoded on the way out. A service that decodes its path twice could
    // still be walked, but that is the service's own parser and guard has handed
    // it one segment rather than a path it assembled.
    await gateway(TABLE, upstream).request("/v1/pantry/%252e%252e/admin", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(upstream.calls[0]?.url).toBe("http://pantry.test:8080/%252e%252e/admin");
  });

  test("a segment that decodes to a separator cannot smuggle a path through", async () => {
    // Structural rather than filtered: the path is rebuilt from decoded,
    // re-encoded segments, so `/v1/pantry/items%2f..%2f..%2fadmin` has no
    // spelling that reaches the service as anything but a literal segment.
    expect(upstreamPath("/v1/pantry", "/v1/pantry/items")).toBe("/items");
    expect(upstreamPath("/v1/pantry", "/v1/pantry/a%2Fb")).toBeNull();
    expect(upstreamPath("/v1/pantry", "/v1/pantry/a%2f..%2fadmin")).toBeNull();
    expect(upstreamPath("/v1/pantry", "/v1/pantry")).toBe("/");
    expect(upstreamPath("/v1/pantry", "/v1/pantry/")).toBe("/");
    // A trailing slash is not a segment; an interior one is a doubled slash,
    // which is not a path.
    expect(upstreamPath("/v1/pantry", "/v1/pantry/items/")).toBe("/items");
    expect(upstreamPath("/v1/pantry", "/v1/pantry//items")).toBeNull();
    expect(upstreamPath("/v1/pantry", "/v1/pantry/%2e%2e")).toBeNull();
  });

  test("a body crosses, and a GET carries none", async () => {
    const app = gateway(TABLE, upstream);

    await app.request("/v1/pantry/items", {
      method: "POST",
      headers: { authorization: `Bearer ${await token()}`, "content-type": "application/json" },
      body: JSON.stringify({ name: "oats" }),
    });
    await app.request("/v1/pantry/items", { headers: { authorization: `Bearer ${await token()}` } });

    expect(upstream.calls[0]?.method).toBe("POST");
    expect(upstream.calls[0]?.body).toBe(`{"name":"oats"}`);
    // A GET with a body is a request a service has to make sense of, and guard
    // would be the one that put it there.
    expect(upstream.calls[1]?.method).toBe("GET");
    expect(upstream.calls[1]?.body).toBe("");
  });
});

// ------------------------------------------------- the credential, and who picks it

describe("the credential on a routed request is guard's", () => {
  let upstream: ReturnType<typeof recorder>;

  beforeEach(() => {
    upstream = recorder();
  });
  test("a caller's Authorization does not reach the service, and guard's does", async () => {
    // THE security claim of the routing packet, and the reason it is a test
    // rather than a comment: guard verifies the caller's token and then presents
    // its own. A caller who can set an arbitrary `Authorization` and have it
    // arrive at pantry has turned guard into a deputy that authenticates them to
    // the edge and lets them choose who they are behind it.
    const caller = `Bearer ${await token()}`;

    const res = await gateway(TABLE, upstream).request("/v1/pantry/items", {
      headers: { authorization: caller },
    });

    expect(res.status).toBe(200);
    const sent = upstream.calls[0]?.headers.get("authorization");
    expect(sent).toBe("Bearer svc-pantry-token");
    // Not merely "different": the caller's token must be nowhere in the header,
    // and a substring check is what catches an implementation that appends it.
    expect(sent).not.toContain(caller);
    expect(sent?.replace("Bearer svc-pantry-token", "")).not.toContain("ey");
  });

  test("the caller's Authorization does not reach a service with no configured token either", async () => {
    // The other half, and the one a "just forward it" implementation gets wrong
    // first: with no token configured, guard sends *no* Authorization header.
    // Absence and substitution are different, and only one of them is safe.
    const res = await gateway(TABLE, upstream).request("/v1/quiet/items", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(200);
    expect(upstream.calls[0]?.headers.get("authorization")).toBeNull();
  });

  test("no cookie crosses, including the BFF session", async () => {
    // The three traffic shapes do not cross. A browser holds
    // `__Host-bff-session`; a service must never see it, and a service that
    // answers with one must never be able to write it (see the relay case below).
    await gateway(TABLE, upstream).request("/v1/pantry/items", {
      headers: {
        authorization: `Bearer ${await token()}`,
        cookie: `${SESSION_COOKIE}=00000000-0000-4000-8000-000000000000`,
      },
    });

    expect(upstream.calls[0]?.headers.get("cookie")).toBeNull();
  });

  test("the forwarded headers are the two that describe the body, and nothing else", async () => {
    // The allowlist, asserted on the wire rather than by reading the constant: a
    // header somebody added to `FORWARDED_REQUEST_HEADERS` for convenience is
    // exactly the change this catches.
    await gateway(TABLE, upstream).request("/v1/pantry/items", {
      method: "POST",
      headers: {
        authorization: `Bearer ${await token()}`,
        "content-type": "application/json",
        accept: "application/problem+json",
        "x-forwarded-for": "203.0.113.4",
        "x-request-id": "caller-chosen",
        "user-agent": "curl/8",
      },
      body: "{}",
    });

    const names = [...upstream.calls[0]!.headers.keys()].sort();
    expect(names).toEqual(["accept", "authorization", "content-type"]);
  });

  test("routed traffic is authenticated before it is forwarded", async () => {
    // The order the whole design rests on, asserted from the outside: an
    // anonymous request to a configured prefix is refused and no service is
    // contacted, which is what the `/v1/*` gate above the mount buys.
    const res = await gateway(TABLE, upstream).request("/v1/pantry/items");

    expect(res.status).toBe(401);
    expect(upstream.calls).toHaveLength(0);
  });

  test("guard's own `/v1/me` is served by guard and reaches no service", async () => {
    // The mount order, read off the behaviour. `/v1/me` is registered before the
    // pass-through, so Hono answers it first — and the table in this file claims
    // `/v1`, so a mount registered above it would proxy the platform's only
    // auth-proof route to whichever service an operator named.
    const app = createApp({
      jwt: { issuer: identity.issuer, audience: AUDIENCE },
      routes: { "/v1": { baseUrl: "http://identity.test", token: "svc-identity" } },
      proxy: { fetch: upstream.fetch },
    });

    const res = await app.request("/v1/me", { headers: { authorization: `Bearer ${await token()}` } });

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ sub: ACCOUNT });
    expect(upstream.calls).toHaveLength(0);
  });
});

// --------------------------------------------------------------- what comes back

describe("a failure behind the edge is guard's to translate", () => {
  let upstream: ReturnType<typeof recorder>;

  beforeEach(() => {
    upstream = recorder();
  });
  /** A 500 carrying everything a stack trace and a topology leak look like. */
  const LEAKY = "panic: runtime error\n\tat pantry/internal/api.go:88\nconnect ECONNREFUSED 10.0.3.7:5432 (http://pantry.test:8080)";

  test("a 500 from a service does not arrive with its address, its port or its stack", async () => {
    upstream.answerWith(() => new Response(LEAKY, { status: 500, headers: { "content-type": "text/plain" } }));

    const res = await gateway(TABLE, upstream).request("/v1/pantry/items", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(503);
    expect(res.headers.get("content-type")).toContain("application/problem+json");
    const body = await res.text();
    for (const secret of ["10.0.3.7", "5432", "ECONNREFUSED", "panic", "api.go", "pantry.test", "8080"]) {
      expect(body, `the body leaked ${secret}`).not.toContain(secret);
    }
    // The reason is a fixed sentence per case, and `detail` is where a caller
    // reads it — so it must not be an echo of anything the service said.
    expect(JSON.parse(body)).toMatchObject({ status: 503, code: "unavailable" });
  });

  test("a service that cannot be reached does not answer with the socket error", async () => {
    // `site/src/lib/upstream.ts` calls this out as the single most reliable way
    // to hand out internal topology: a fetch error message is
    // `connect ECONNREFUSED 10.0.3.7:8080`.
    upstream.answerWith(() => {
      throw new Error("connect ECONNREFUSED 10.0.3.7:8080");
    });

    const res = await gateway(TABLE, upstream).request("/v1/pantry/items", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(503);
    const body = await res.text();
    for (const secret of ["10.0.3.7", "8080", "ECONNREFUSED", "pantry.test"]) {
      expect(body, `the body leaked ${secret}`).not.toContain(secret);
    }
  });

  test("the failure is written down, with the target and the status", async () => {
    // The other half of the rule, and the half that used to be missing
    // everywhere in this repository before guard-07: a 503 with no log line is
    // an operator with nothing to correlate against.
    const logged: unknown[][] = [];
    const real = console.error;
    console.error = (...args: unknown[]) => void logged.push(args);
    upstream.answerWith(() => new Response(LEAKY, { status: 500 }));

    try {
      await gateway(TABLE, upstream).request("/v1/pantry/items", {
        headers: { authorization: `Bearer ${await token()}` },
      });
    } finally {
      console.error = real;
    }

    const line = JSON.stringify(logged);
    expect(line).toContain("pantry.test:8080/items");
    expect(line).toContain("500");
    expect(line).toContain("not JSON");
    // And the service's own body is not what got logged, for the same reason it
    // is not in the response.
    expect(line).not.toContain("ECONNREFUSED");
  });

  test("a 2xx and a 4xx cross unchanged, because they are the service's own contract", async () => {
    // A 401 that became a 200 reports a refusal as a success; a 422 that became
    // a 400 drops the field errors a sign-in form turns into sentences.
    for (const [status, body] of [
      [200, { items: [1, 2] }],
      [404, { code: "not_found", detail: "no such item" }],
      [422, { code: "validation_failed", errors: [{ field: "name", code: "required" }] }],
    ] as const) {
      const fresh = recorder();
      fresh.answerWith(() => Response.json(body, { status }));

      const res = await gateway(TABLE, fresh).request("/v1/pantry/items", {
        headers: { authorization: `Bearer ${await token()}` },
      });

      expect(res.status).toBe(status);
      expect(await res.json()).toEqual(body);
    }
  });

  test("a redirect is translated rather than followed or relayed", async () => {
    // `fetch` follows a 3xx by default, and the `Location` an internal service
    // answers with is an address that is not on the internet. Both halves are
    // wrong — following it and relaying it — so a 3xx is translated.
    upstream.answerWith(() => new Response(null, { status: 302, headers: { location: "http://10.0.3.7:8080/" } }));

    const res = await gateway(TABLE, upstream).request("/v1/pantry/items", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(503);
    expect(res.headers.get("location")).toBeNull();
    expect(await res.text()).not.toContain("10.0.3.7");
  });

  test("a service cannot write the browser's session cookie", async () => {
    // Not tidiness. A service answering `Set-Cookie: __Host-bff-session=…` would
    // be writing the browser's BFF session from behind the edge on an origin
    // where the `__Host-` prefix is honoured, which is session fixation arriving
    // through the gateway.
    upstream.answerWith(() =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "set-cookie": `${SESSION_COOKIE}=forged-session-id`,
        },
      }),
    );

    const res = await gateway(TABLE, upstream).request("/v1/pantry/items", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("only the header that says what the body is crosses back", async () => {
    upstream.answerWith(
      () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: {
            "content-type": "application/json",
            server: "pantry/1.4.2 (go1.24)",
            "x-powered-by": "internal",
          },
        }),
    );

    const res = await gateway(TABLE, upstream).request("/v1/pantry/items", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.headers.get("content-type")).toContain("application/json");
    // A `Server` header names the internal service and its version, and no
    // client in this repository reads it.
    expect(res.headers.get("server")).toBeNull();
    expect(res.headers.get("x-powered-by")).toBeNull();
    // The one header added rather than forwarded, for the reason in `relay`.
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});

// ------------------------------------------------------------- bounded, and counted

describe("a routed call is bounded in time and counted by the limiter", () => {
  test("a service that never answers does not hold the request open", async () => {
    const upstream = recorder();
    upstream.answerWith(() => new Promise<Response>(() => {}));

    const app = createApp({
      routes: TABLE,
      proxy: { fetch: upstream.fetch, timeoutMs: 25 },
      jwt: { issuer: identity.issuer, audience: AUDIENCE },
    });

    const res = await app.request("/v1/pantry/items", { headers: { authorization: `Bearer ${await token()}` } });

    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain("pantry.test");
  });

  test("a timeout that is not an integer >= 1 is a startup error", async () => {
    expect(() => createRouteProxy({ routes: routeTable(TABLE), timeoutMs: 0 })).toThrow(RangeError);
    expect(() => createRouteProxy({ routes: routeTable(TABLE), timeoutMs: 1.5 })).toThrow(RangeError);
  });

  test("a routed route can be throttled, which is what makes the limit table's `/v1/` row real", async () => {
    // The claim that a route which proxies is a route that can be abused, and
    // that the limiter is above the mount. The assertion is the 429, not the
    // 200 — a limiter mounted after the pass-through answers 200 forever and
    // this case cannot tell the difference.
    const upstream = recorder();
    const app = createApp({
      routes: TABLE,
      proxy: { fetch: upstream.fetch },
      rateLimit: { limits: { default: { limit: 2, windowMs: 60_000, policy: "guard-api" }, routes: {} } },
      jwt: { issuer: identity.issuer, audience: AUDIENCE },
    });
    const bearer = `Bearer ${await token()}`;

    expect((await app.request("/v1/pantry/items", { headers: { authorization: bearer } })).status).toBe(200);
    expect((await app.request("/v1/pantry/items", { headers: { authorization: bearer } })).status).toBe(200);

    const refused = await app.request("/v1/pantry/items", { headers: { authorization: bearer } });
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toBeTruthy();
    // Two requests reached the service; the third never did, because the limiter
    // is above the mount rather than inside it.
    expect(upstream.calls).toHaveLength(2);
  });

  test("an app built with no route table forwards nothing", async () => {
    const upstream = recorder();
    const app = createApp({
      proxy: { fetch: upstream.fetch },
      jwt: { issuer: identity.issuer, audience: AUDIENCE },
    });

    const res = await app.request("/v1/pantry/items", { headers: { authorization: `Bearer ${await token()}` } });

    expect(res.status).toBe(404);
    expect(upstream.calls).toHaveLength(0);
  });
});