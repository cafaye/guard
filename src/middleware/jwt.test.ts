import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { Hono } from "hono";
import type { JWTPayload } from "jose";
import { createJwtVerifier, DEFAULT_IDENTITY_ISSUER, JWKS_PATH, type AuthEnv, type JwtOptions } from "./jwt";
import {
  signToken,
  startJwksServer,
  tamperPayload,
  testKey,
  unsignedToken,
  type JwksServer,
  type TestKey,
} from "../../test/jwksServer";

const AUDIENCE = "guard-test";

let identity: JwksServer;
/** Published by default. */
let key: TestKey;
/** Published only when a test rotates the key set. */
let rotated: TestKey;

beforeAll(async () => {
  // Two real RSA key pairs, generated once for the file: a token signed by one
  // and published as the other is the shape of a forgery, and a rotation is
  // the shape of identity adding a key.
  key = await testKey("key-1");
  rotated = await testKey("key-2");
  identity = await startJwksServer(key);
});

afterAll(() => identity.stop());

/**
 * The log is where an underlying failure belongs, so it is captured here rather
 * than printed: the identity outage cases assert that the reason reached the log
 * and not the response, and the suite's output stays readable.
 */
const logged: unknown[][] = [];
let realConsoleError: typeof console.error;

beforeEach(() => {
  identity.publish(key);
  identity.serveKeys();
  identity.requests.length = 0;

  logged.length = 0;
  realConsoleError = console.error;
  console.error = (...args: unknown[]) => void logged.push(args);
});

afterEach(() => {
  console.error = realConsoleError;
});

/** Seconds since the epoch, the unit JWT time claims use. */
const seconds = (offset = 0): number => Math.floor(Date.now() / 1000) + offset;

/** A token that passes every check, plus whatever the case is about. */
function validToken(overrides: JWTPayload = {}): Promise<string> {
  return signToken(key, {
    iss: identity.issuer,
    aud: AUDIENCE,
    sub: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    iat: seconds(),
    exp: seconds(60),
    scope: "billing.read profile.read",
    ...overrides,
  });
}

/**
 * The gateway with the auth chain mounted the way `createApp` mounts it: every
 * `/private/*` route behind `requireJwt`, one of them also behind a scope gate.
 */
function app(options: Partial<JwtOptions> = {}) {
  const gateway = new Hono<AuthEnv>();
  const jwt = createJwtVerifier({ issuer: identity.issuer, audience: AUDIENCE, ...options });

  gateway.use("/private/*", jwt.requireJwt);
  gateway.get("/private/thing", (c) => c.json({ ok: true }));
  gateway.get(
    "/private/billing",
    jwt.requireScope("billing.read"),
    (c) => c.json({ ok: true, sub: c.get("principal").sub }),
  );

  return gateway;
}

const bearer = (token: string): RequestInit => ({ headers: { Authorization: `Bearer ${token}` } });

type ProblemBody = {
  type?: unknown;
  title?: unknown;
  status?: unknown;
  detail?: unknown;
  instance?: unknown;
  code?: unknown;
  trace_id?: unknown;
};

/**
 * Asserts a rejection against core's error envelope, in full: the media type,
 * every field, and the `X-Trace-Id` header matching the body. Asserting the
 * whole envelope on every case is the point — a 401 with the right status and
 * the wrong shape is still a broken contract for every client that reads it.
 */
async function expectProblem(
  res: Response,
  expected: { status: number; code: string; detail: string; instance: string },
): Promise<ProblemBody> {
  expect(res.status).toBe(expected.status);
  expect(res.headers.get("content-type")).toContain("application/problem+json");

  const body = (await res.json()) as ProblemBody;
  const traceId = res.headers.get("x-trace-id");

  expect(body.type).toBe(`https://errors.cafaye.com/${expected.code}`);
  expect(body.code).toBe(expected.code);
  expect(body.status).toBe(expected.status);
  expect(body.detail).toBe(expected.detail);
  expect(body.instance).toBe(expected.instance);
  expect(typeof body.title).toBe("string");
  // core: trace_id is always present and always matches the X-Trace-Id header.
  expect(body.trace_id).toBe(traceId);
  expect(traceId).toMatch(/^[0-9a-f]{32}$/);

  return body;
}

describe("requireJwt — accepts a token the contract allows", () => {
  test("a valid bearer token reaches the handler", async () => {
    const res = await app().request("/private/thing", bearer(await validToken()));

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ ok: true });
  });

  test("the verified principal is on the context: sub, scope and the claims", async () => {
    const gateway = new Hono<AuthEnv>();
    const jwt = createJwtVerifier({ issuer: identity.issuer, audience: AUDIENCE });
    gateway.use("/private/*", jwt.requireJwt);
    gateway.get("/private/thing", (c) => c.json(c.get("principal")));

    const token = await validToken();
    const res = await gateway.request("/private/thing", bearer(token));

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      sub: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      scope: ["billing.read", "profile.read"],
      claims: {
        iss: identity.issuer,
        aud: AUDIENCE,
        sub: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        iat: expect.any(Number),
        exp: expect.any(Number),
        scope: "billing.read profile.read",
      },
    });
  });

  test("the credential is the Authorization header, never a cookie", async () => {
    const res = await app().request("/private/thing", {
      headers: { Cookie: "session=eyJhbGciOiJSUzI1NiJ9.fake.sig" },
    });

    await expectProblem(res, {
      status: 401,
      code: "unauthorized",
      detail: "a bearer token is required",
      instance: "/private/thing",
    });
  });

  test("the scheme is case-insensitive, as RFC 6750 requires", async () => {
    const res = await app().request("/private/thing", {
      headers: { Authorization: `bearer ${await validToken()}` },
    });

    expect(res.status).toBe(200);
  });

  test("a token with no scope claim is accepted: the claim is optional", async () => {
    const token = await validToken({ scope: undefined });
    const res = await app().request("/private/thing", bearer(token));

    expect(res.status).toBe(200);
  });

  test("a JWKS URL may be configured separately from the issuer", async () => {
    // The shape a deployment has in production: a real issuer in the `iss`
    // claim, and the key set wherever the operator points it.
    const gateway = app({ issuer: "https://identity.example", jwksUrl: identity.jwksUrl });
    const token = await signToken(key, {
      iss: "https://identity.example",
      aud: AUDIENCE,
      sub: "user-1",
      exp: seconds(60),
    });

    const res = await gateway.request("/private/thing", bearer(token));

    expect(res.status).toBe(200);
    expect(identity.requests).toEqual(["/.well-known/jwks.json"]);
  });
});

describe("requireJwt — refuses everything the contract says to refuse", () => {
  const cases: { name: string; token: () => Promise<string> | string; detail: string }[] = [
    {
      name: "an expired token",
      token: () => validToken({ iat: seconds(-600), exp: seconds(-300) }),
      detail: "token has expired",
    },
    {
      name: "a token from another issuer",
      token: () => validToken({ iss: "https://identity.evil.example" }),
      detail: "token claim 'iss' is not valid",
    },
    {
      name: "a token addressed to another client",
      token: () => validToken({ aud: "another-gateway" }),
      detail: "token claim 'aud' is not valid",
    },
    {
      name: "a token that is not valid yet",
      token: () => validToken({ nbf: seconds(600) }),
      detail: "token claim 'nbf' is not valid",
    },
    {
      name: "a token whose payload was edited after signing",
      token: async () => tamperPayload(await validToken(), { iss: identity.issuer, sub: "someone-else" }),
      detail: "token signature does not verify",
    },
    {
      name: "a token signed by a key identity does not publish",
      token: () => signToken(rotated, { iss: identity.issuer, aud: AUDIENCE, sub: "u", exp: seconds(60) }, { kid: "key-2" }),
      detail: "token was signed by an unknown key",
    },
    {
      name: "an unsigned token (alg none)",
      token: () => unsignedToken({ iss: identity.issuer, sub: "u" }, { alg: "none", typ: "JWT" }),
      detail: "token algorithm 'none' is not accepted",
    },
    {
      name: "an HS256 token, the symmetric downgrade",
      token: () => unsignedToken({ iss: identity.issuer, sub: "u" }, { alg: "HS256", typ: "JWT" }),
      detail: "token algorithm 'HS256' is not accepted",
    },
    {
      name: "a token with no key id in its header",
      token: () => signToken(key, { iss: identity.issuer, sub: "u", exp: seconds(60) }, { kid: undefined }),
      detail: "token header names no key",
    },
    {
      name: "a token with no subject",
      token: () => validToken({ sub: undefined }),
      detail: "token has no subject",
    },
    {
      name: "a scope claim that is not a string",
      token: () => validToken({ scope: ["billing.read"] as unknown as string }),
      detail: "token scope claim is not a string",
    },
    {
      name: "a token that is not a JWT at all",
      token: () => "not-a-token",
      detail: "token is malformed",
    },
    {
      name: "a three-segment string that is not base64url JSON",
      token: () => "aaa.bbb.ccc",
      detail: "token is malformed",
    },
    {
      name: "a token with no signature segment",
      token: () => "aaa.bbb.",
      detail: "token is malformed",
    },
  ];

  for (const { name, token, detail } of cases) {
    test(`401 for ${name}`, async () => {
      const res = await app().request("/private/thing", bearer(await token()));

      await expectProblem(res, { status: 401, code: "unauthorized", detail, instance: "/private/thing" });
    });
  }

  const missing: { name: string; headers: Record<string, string> }[] = [
    { name: "no Authorization header", headers: {} },
    { name: "an empty Authorization header", headers: { Authorization: "" } },
    { name: "a whitespace-only Authorization header", headers: { Authorization: "   " } },
    { name: "a Basic credential", headers: { Authorization: "Basic dXNlcjpwYXNz" } },
    { name: "a bare scheme with no token", headers: { Authorization: "Bearer" } },
    { name: "two tokens after the scheme", headers: { Authorization: "Bearer aaa.bbb.ccc ddd.eee.fff" } },
  ];

  for (const { name, headers } of missing) {
    test(`401 for ${name}`, async () => {
      const res = await app().request("/private/thing", { headers });

      await expectProblem(res, {
        status: 401,
        code: "unauthorized",
        detail: "a bearer token is required",
        instance: "/private/thing",
      });
    });
  }
});

describe("requireJwt — the algorithm is guard's decision, not the token's", () => {
  test("a rejected algorithm header is refused before any key is fetched", async () => {
    // An attacker who can pick the header must not be able to make guard call
    // identity: one request, one signature to check, no network.
    const res = await app().request(
      "/private/thing",
      bearer(unsignedToken({ iss: identity.issuer, sub: "u" }, { alg: "none", typ: "JWT" })),
    );

    expect(res.status).toBe(401);
    expect(identity.requests).toEqual([]);
  });

  test("RS256 is the only algorithm accepted", async () => {
    // core's conventions allow RS256 and ES256; the packet's contract fixes
    // RS256. Narrowing is a deny, so it fails closed either way.
    const res = await app().request(
      "/private/thing",
      bearer(unsignedToken({ iss: identity.issuer, sub: "u" }, { alg: "ES256", typ: "JWT" })),
    );

    expect(res.status).toBe(401);
    expect(identity.requests).toEqual([]);
  });
});

describe("the JWKS cache", () => {
  /** A verifier whose clock is the test's, so the TTL needs no sleeping. */
  function clockedApp(ttlMs?: number) {
    let clock = 1_000_000;
    const gateway = app({ jwksCacheTtlMs: ttlMs, now: () => clock });
    return { gateway, advance: (ms: number) => (clock += ms) };
  }

  test("the first token fetches the keys; the next ones reuse them", async () => {
    const { gateway } = clockedApp();

    for (let i = 0; i < 5; i++) {
      expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);
    }

    expect(identity.requests).toHaveLength(1);
  });

  test("the default TTL is 300 seconds", async () => {
    const { gateway, advance } = clockedApp();

    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);
    advance(299_999);
    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);
    expect(identity.requests).toHaveLength(1);

    advance(1);
    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);
    expect(identity.requests).toHaveLength(2);
  });

  test("a configured TTL is honoured", async () => {
    const { gateway, advance } = clockedApp(1_000);

    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);
    advance(999);
    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);
    expect(identity.requests).toHaveLength(1);

    advance(1);
    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);
    expect(identity.requests).toHaveLength(2);
  });

  test("the issuer is a base URL: the JWKS path is appended to it", async () => {
    // A trailing slash is what an operator types out of habit, and
    // `issuer + path` must not become a `//` the endpoint does not answer.
    const gateway = app({ issuer: `${identity.issuer}/` });

    const res = await gateway.request("/private/thing", bearer(await validToken()));

    expect(res.status).toBe(200);
    expect(identity.requests).toEqual(["/.well-known/jwks.json"]);
  });
});

describe("key rotation", () => {
  test("an unknown kid forces one refresh, and the new key then verifies", async () => {
    // identity has rotated to key-2 while guard's cache holds key-1. This is
    // the only reason a JWKS refresh is allowed on the hot path.
    const gateway = app();
    const stale = await gateway.request("/private/thing", bearer(await validToken()));
    expect(stale.status).toBe(200);
    expect(identity.requests).toHaveLength(1);

    identity.publish(rotated);
    const fresh = await signToken(rotated, {
      iss: identity.issuer,
      aud: AUDIENCE,
      sub: "user-1",
      exp: seconds(60),
    });
    const res = await gateway.request("/private/thing", bearer(fresh));

    expect(res.status).toBe(200);
    // One cached fetch plus exactly one forced refresh.
    expect(identity.requests).toHaveLength(2);
  });

  test("an unknown kid that stays unknown fails after one refresh, not a loop", async () => {
    const gateway = app();

    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);

    const forged = await signToken(rotated, {
      iss: identity.issuer,
      aud: AUDIENCE,
      sub: "u",
      exp: seconds(60),
    });
    const unknown = await gateway.request("/private/thing", bearer(forged));

    await expectProblem(unknown, {
      status: 401,
      code: "unauthorized",
      detail: "token was signed by an unknown key",
      instance: "/private/thing",
    });
    // Cached + one forced refresh. A second attempt must not fetch again: that
    // is the difference between one refresh for a rotation and an amplifier
    // pointed at identity.
    expect(identity.requests).toHaveLength(2);

    const again = await gateway.request("/private/thing", bearer(forged));

    expect(again.status).toBe(401);
    expect(identity.requests).toHaveLength(2);
  });

  test("a burst of unknown kids buys one refresh, not one per request", async () => {
    // The sequential case above is not the shape an attacker sends. A forged
    // token is free to make twenty-five requests that all arrive *before* the
    // first forced refresh has answered, and the budget the source names — "one
    // forced refresh per cache window" — has to hold for the arrival order a
    // real edge produces, not only for a loop of `await`s.
    //
    // This is pre-auth and unauthenticated: the caller needs no valid token to
    // reach it, only a token-shaped string naming a key identity does not
    // publish. Every one of those requests aims a fetch at identity, so the
    // limiter's whole answer to it has to be a number.
    const gateway = app();
    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(200);
    expect(identity.requests).toHaveLength(1);

    const forged = await signToken(rotated, {
      iss: identity.issuer,
      aud: AUDIENCE,
      sub: "u",
      exp: seconds(60),
    });

    const burst = await Promise.all(
      Array.from({ length: 25 }, () => gateway.request("/private/thing", bearer(forged))),
    );

    for (const res of burst) {
      await expectProblem(res, {
        status: 401,
        code: "unauthorized",
        detail: "token was signed by an unknown key",
        instance: "/private/thing",
      });
    }

    // One cached fetch plus exactly one forced refresh, however many arrived at
    // once. Anything above two is the amplifier this rule exists to prevent.
    expect(identity.requests).toHaveLength(2);
  });

  test("a key identity retracts keeps working until the cache expires", async () => {
    // The TTL is the revocation window, which is why it is configuration and
    // not a constant. Anyone shortening it is trading identity's load for how
    // fast a retracted key stops working.
    let clock = 1_000_000;
    const gateway = app({ now: () => clock });
    const token = await validToken();

    expect((await gateway.request("/private/thing", bearer(token))).status).toBe(200);

    identity.publish(rotated);
    expect((await gateway.request("/private/thing", bearer(token))).status).toBe(200);

    clock += 300_000;
    const res = await gateway.request("/private/thing", bearer(token));

    expect(res.status).toBe(401);
    expect(identity.requests).toHaveLength(2);
  });
});

describe("when identity cannot be reached", () => {
  test("503 when the JWKS endpoint is down", async () => {
    identity.failWith(503);

    const res = await app().request("/private/thing", bearer(await validToken()));

    await expectProblem(res, {
      status: 503,
      code: "unavailable",
      detail: "the signing keys could not be retrieved",
      instance: "/private/thing",
    });
  });

  test("503 when the JWKS endpoint answers with something that is not a key set", async () => {
    // An intercepting proxy answering 200 is a shape guard must survive.
    identity.serveGarbage();

    const res = await app().request("/private/thing", bearer(await validToken()));

    expect(res.status).toBe(503);
    expect(((await res.json()) as ProblemBody).code).toBe("unavailable");
  });

  test("503 when the JWKS endpoint never answers", async () => {
    identity.hang();

    const res = await app({ jwksTimeoutMs: 25 }).request("/private/thing", bearer(await validToken()));

    expect(res.status).toBe(503);
    expect(((await res.json()) as ProblemBody).code).toBe("unavailable");
  });

  test("a failed fetch never leaks the identity host, port or key URL", async () => {
    identity.failWith(500);

    const res = await app().request("/private/thing", bearer(await validToken()));
    const text = await res.text();

    expect(text).not.toContain(identity.issuer);
    expect(text).not.toContain(String(identity.jwksUrl));
    expect(text).not.toContain("127.0.0.1");
  });

  test("the failure behind the 503 is logged, not returned", async () => {
    identity.failWith(500);

    const res = await app().request("/private/thing", bearer(await validToken()));

    // The log is where the host and the status code belong; the response body is
    // for the caller. This test is the pair of halves of that rule.
    expect(logged).toHaveLength(1);
    expect(String(logged[0]?.[1])).toContain(identity.jwksUrl);
    expect(await res.text()).not.toContain(identity.jwksUrl);
  });

  test("an outage does not poison the cache: the next good fetch works", async () => {
    identity.failWith(500);
    const gateway = app();
    expect((await gateway.request("/private/thing", bearer(await validToken()))).status).toBe(503);

    identity.serveKeys();
    const res = await gateway.request("/private/thing", bearer(await validToken()));

    expect(res.status).toBe(200);
  });
});

describe("requireScope", () => {
  test("a token carrying the scope reaches the handler", async () => {
    const res = await app().request("/private/billing", bearer(await validToken()));

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, sub: "3f2504e0-4f89-41d3-9a0c-0305e82c3301" });
  });

  test("403 when the token does not carry the scope", async () => {
    const res = await app().request("/private/billing", bearer(await validToken({ scope: "profile.read" })));

    await expectProblem(res, {
      status: 403,
      code: "forbidden",
      detail: "token is missing the billing.read scope",
      instance: "/private/billing",
    });
  });

  test("403 when the token carries no scope claim at all", async () => {
    // An absent claim is an empty scope set, not an open door.
    const res = await app().request("/private/billing", bearer(await validToken({ scope: undefined })));

    expect(res.status).toBe(403);
  });

  test("403 names the scope that is missing, and never the ones that are held", async () => {
    const res = await app().request("/private/billing", bearer(await validToken({ scope: "profile.read admin" })));

    const text = await res.text();
    expect(text).toContain("billing.read");
    expect(text).not.toContain("profile.read");
    expect(text).not.toContain("admin");
  });

  test("401 when the scope gate is mounted without the auth gate", async () => {
    // A wiring mistake, not an authorization decision: nothing has been proven,
    // so the answer is 401 and not 403.
    const gateway = new Hono<AuthEnv>();
    const jwt = createJwtVerifier({ issuer: identity.issuer, audience: AUDIENCE });
    gateway.get("/private/billing", jwt.requireScope("billing.read"), (c) => c.json({ ok: true }));

    const res = await gateway.request("/private/billing");

    await expectProblem(res, {
      status: 401,
      code: "unauthorized",
      detail: "a bearer token is required",
      instance: "/private/billing",
    });
  });

  test("an empty scope is a configuration error, not a gate that allows everything", async () => {
    const jwt = createJwtVerifier({ issuer: identity.issuer, audience: AUDIENCE });

    expect(() => jwt.requireScope("")).toThrow(RangeError);
    expect(() => jwt.requireScope("   ")).toThrow(RangeError);
  });
});

describe("configuration is validated, not guessed", () => {
  test("the default issuer and JWKS path are the contract's, spelled out", () => {
    // What the packet fixes, in one place, so a drift here is a test failure
    // rather than a surprise at 3am against a real identity.
    expect(`${DEFAULT_IDENTITY_ISSUER}${JWKS_PATH}`).toBe("https://identity.localhost/.well-known/jwks.json");
  });

  test("an empty issuer is rejected", () => {
    expect(() => createJwtVerifier({ issuer: "  ", audience: AUDIENCE })).toThrow(RangeError);
  });

  test("an issuer that is not an absolute http(s) URL is rejected", () => {
    for (const issuer of ["identity.localhost", "/identity", "ftp://identity.example", "https://"]) {
      expect(() => createJwtVerifier({ issuer, audience: AUDIENCE })).toThrow(RangeError);
    }
  });

  test("an issuer with a path is rejected: the JWKS path is appended to it", () => {
    expect(() => createJwtVerifier({ issuer: "https://identity.example/tenants/acme", audience: AUDIENCE })).toThrow(
      RangeError,
    );
  });

  test("a key-set URL that is not an absolute http(s) URL is rejected", () => {
    for (const jwksUrl of ["keys.example/jwks.json", "/jwks.json", "ftp://keys.example/jwks.json"]) {
      expect(() => createJwtVerifier({ issuer: identity.issuer, audience: AUDIENCE, jwksUrl })).toThrow(RangeError);
    }
  });

  test("a key-set URL with a path is used exactly as configured", async () => {
    // The mock only serves the well-known path, so this answers 503 — what
    // matters is that the fetch went where the operator said, verbatim.
    const jwksUrl = `${identity.issuer}/keys/v2.json`;
    const res = await app({ jwksUrl }).request("/private/thing", bearer(await validToken()));

    expect(res.status).toBe(503);
    expect(identity.requests).toEqual(["/keys/v2.json"]);
  });

  test("an empty audience is rejected", () => {
    expect(() => createJwtVerifier({ issuer: identity.issuer, audience: "" })).toThrow(RangeError);
  });

  test("a zero, negative or fractional TTL is rejected", () => {
    for (const ttl of [0, -1, 1.5, Number.NaN]) {
      expect(() => createJwtVerifier({ issuer: identity.issuer, audience: AUDIENCE, jwksCacheTtlMs: ttl })).toThrow(
        RangeError,
      );
    }
  });

  test("a zero or negative fetch timeout is rejected", () => {
    for (const ms of [0, -1]) {
      expect(() => createJwtVerifier({ issuer: identity.issuer, audience: AUDIENCE, jwksTimeoutMs: ms })).toThrow(
        RangeError,
      );
    }
  });
});
