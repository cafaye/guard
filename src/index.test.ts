import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createApp, runtimeOptions, type ProbeStatus } from "./index";
import { createApiKeyAuth, memoryApiKeyStore } from "./middleware/apiKey";
import { DEFAULT_LIMIT_TABLE } from "./middleware/limits";
import { signToken, startJwksServer, testKey, type JwksServer, type TestKey } from "../test/jwksServer";
import { strictTable } from "../test/limitTable";

describe("GET /healthz", () => {
  test("200 with the exact ok body", async () => {
    const res = await createApp().request("/healthz");

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ status: "ok" });
  });

  test("needs no Authorization header", async () => {
    expect((await createApp().request("/healthz")).status).toBe(200);
  });
});

describe("GET /readyz", () => {
  test("200 and a deps object when every probe reports ok", async () => {
    const app = createApp({ probes: { core: () => "ok", identity: () => "ok" } });

    const res = await app.request("/readyz");

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ deps: { core: "ok", identity: "ok" } });
  });

  test("v0 default: no probes means ready with an empty deps object", async () => {
    const res = await createApp().request("/readyz");

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ deps: {} });
  });

  test("503 when a probe reports a dependency as unavailable", async () => {
    const app = createApp({
      probes: { core: () => "ok", identity: async (): Promise<ProbeStatus> => "unavailable" },
    });

    const res = await app.request("/readyz");

    expect(res.status).toBe(503);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ deps: { core: "ok", identity: "unavailable" } });
  });

  test("503 when a probe throws", async () => {
    const app = createApp({
      probes: {
        core: () => {
          throw new Error("connection refused");
        },
      },
    });

    const res = await app.request("/readyz");

    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ deps: { core: "unavailable" } });
  });

  test("503 when a probe rejects", async () => {
    const app = createApp({ probes: { core: () => Promise.reject(new Error("timeout")) } });

    expect((await app.request("/readyz")).status).toBe(503);
  });
});

describe("app surface", () => {
  test("unknown routes are 404 JSON, not an unhandled throw", async () => {
    const res = await createApp().request("/nope");

    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ error: "not_found", message: "no such route" });
  });

  test("a throwing handler is a flat JSON 500 and leaks nothing to the caller", async () => {
    const app = createApp();
    // Routes can be added to the app the factory hands back, so the error path
    // is tested without the shipped app owning a route that always fails.
    app.get("/boom", () => {
      throw new Error("dial 10.0.0.5:5432: connection refused");
    });

    const res = await app.request("/boom");

    expect(res.status).toBe(500);
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({
      error: "internal_error",
      message: "unexpected server error",
    });
    // The address goes to the log, never to an unauthenticated caller.
    expect(body).not.toContain("10.0.0.5");
  });

  test("rate limiting never throttles the probe endpoints", async () => {
    const app = createApp({ rateLimit: { limits: strictTable(1) } });

    for (let i = 0; i < 5; i++) {
      expect((await app.request("/healthz")).status).toBe(200);
      expect((await app.request("/readyz")).status).toBe(200);
    }
  });
});

const CLIENT_ID = "guard-test";

/** The account the minted token below acts on, shared with the API-key cases. */
const ACCOUNT = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

let identity: JwksServer;
let key: TestKey;

beforeAll(async () => {
  key = await testKey("key-1");
  identity = await startJwksServer(key);
});

afterAll(() => identity.stop());

const gateway = () => createApp({ jwt: { issuer: identity.issuer, audience: CLIENT_ID } });

const token = () =>
  signToken(key, {
    iss: identity.issuer,
    aud: CLIENT_ID,
    sub: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60,
    scope: "profile.read",
  });

const bearer = (value: string): RequestInit => ({ headers: { Authorization: `Bearer ${value}` } });

describe("GET /v1/me", () => {
  test("echoes the verified claims of the bearer token", async () => {
    const res = await gateway().request("/v1/me", bearer(await token()));

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({
      sub: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      scope: ["profile.read"],
      claims: {
        iss: identity.issuer,
        aud: CLIENT_ID,
        sub: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        iat: expect.any(Number),
        exp: expect.any(Number),
        scope: "profile.read",
      },
    });
  });

  test("401 for an anonymous caller, in core's error envelope", async () => {
    const res = await gateway().request("/v1/me");

    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/problem+json");
    const body = (await res.json()) as { code: string; detail: string; instance: string };
    expect(body).toMatchObject({
      code: "unauthorized",
      detail: "a bearer token is required",
      instance: "/v1/me",
    });
  });

  test("a forged token is refused on the shipped app, not just in the middleware's own app", async () => {
    const res = await gateway().request("/v1/me", bearer("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."));

    expect(res.status).toBe(401);
  });

  test("an unknown /v1 route is 404, and still needs a token first", async () => {
    expect((await gateway().request("/v1/nope")).status).toBe(401);

    const res = await gateway().request("/v1/nope", bearer(await token()));

    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found", message: "no such route" });
  });

  test("the probes are unaffected by the auth chain", async () => {
    const app = gateway();

    expect((await app.request("/healthz")).status).toBe(200);
    expect((await app.request("/readyz")).status).toBe(200);
  });

  test("traffic is rate limited, and so is the request after it", async () => {
    const app = createApp({
      jwt: { issuer: identity.issuer, audience: CLIENT_ID },
      rateLimit: { limits: strictTable(1) },
    });

    expect((await app.request("/v1/me", bearer(await token()))).status).toBe(200);

    const res = await app.request("/v1/me", bearer(await token()));

    expect(res.status).toBe(429);
  });

  test("a token that does not verify 401s and never becomes a rate-limit key", async () => {
    // The requirement, and the reason the limiter is mounted after the auth gate:
    // a credential guard could not verify has no account, so there is nothing to
    // count it against. Keying on an unverified claim would be a limiter any
    // caller can reset by sending a different one.
    const app = createApp({
      jwt: { issuer: identity.issuer, audience: CLIENT_ID },
      rateLimit: { limits: strictTable(1) },
    });

    const refused = [
      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", // alg: none
      "not-a-token",
      "",
    ];
    for (const value of refused) {
      const res = await app.request("/v1/me", bearer(value));

      expect(res.status).toBe(401);
      expect(res.headers.get("ratelimit-limit")).toBeNull();
    }

    // An expired token, which is a well-formed token that is simply too old.
    const expired = await signToken(key, {
      iss: identity.issuer,
      aud: CLIENT_ID,
      sub: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      iat: Math.floor(Date.now() / 1000) - 600,
      exp: Math.floor(Date.now() / 1000) - 300,
    });
    expect((await app.request("/v1/me", bearer(expired))).status).toBe(401);

    // The good token still has its whole allowance: nothing above was counted
    // against the account it claims.
    expect((await app.request("/v1/me", bearer(await token()))).status).toBe(200);
  });

  test("the bucket is the account, so two accounts never share an allowance", async () => {
    const app = createApp({
      jwt: { issuer: identity.issuer, audience: CLIENT_ID },
      rateLimit: { limits: strictTable(1) },
    });
    const other = async () =>
      signToken(key, {
        iss: identity.issuer,
        aud: CLIENT_ID,
        sub: "9c1f0d2a-1111-4222-8333-444455556666",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
      });

    expect((await app.request("/v1/me", bearer(await token()))).status).toBe(200);
    expect((await app.request("/v1/me", bearer(await other()))).status).toBe(200);
    expect((await app.request("/v1/me", bearer(await token()))).status).toBe(429);
  });

  test("an app with no identity configured serves no /v1 surface at all", async () => {
    // Nothing to verify against is not a degraded auth mode; it is a gateway
    // that has not been told who its issuer is, and it says so with a 404
    // rather than an endpoint that would have to trust a token.
    const res = await createApp().request("/v1/me", bearer(await token()));

    expect(res.status).toBe(404);
  });
});

describe("runtimeOptions", () => {
  test("defaults to the local identity issuer and guard's own client id", () => {
    const { jwt } = runtimeOptions({});

    expect(jwt).toEqual({ issuer: "https://identity.localhost", audience: "guard" });
  });

  test("IDENTITY_ISSUER is the issuer-only base URL", () => {
    const { jwt } = runtimeOptions({ IDENTITY_ISSUER: "https://identity.cafaye.com" });

    expect(jwt?.issuer).toBe("https://identity.cafaye.com");
  });

  test("IDENTITY_JWKS_URL overrides where the keys are read from", () => {
    const { jwt } = runtimeOptions({ IDENTITY_JWKS_URL: "https://keys.example/jwks.json" });

    expect(jwt?.jwksUrl).toBe("https://keys.example/jwks.json");
  });

  test("IDENTITY_JWKS_TTL_MS is the cache lifetime in milliseconds", () => {
    expect(runtimeOptions({ IDENTITY_JWKS_TTL_MS: "60000" }).jwt?.jwksCacheTtlMs).toBe(60_000);
  });

  test("GUARD_CLIENT_ID is the audience guard accepts", () => {
    expect(runtimeOptions({ GUARD_CLIENT_ID: "cafaye-console" }).jwt?.audience).toBe("cafaye-console");
  });

  test("an empty variable is unset, not a value", () => {
    // `IDENTITY_ISSUER=` is what an unset variable looks like in a compose file.
    const { jwt } = runtimeOptions({ IDENTITY_ISSUER: "  ", IDENTITY_JWKS_TTL_MS: "" });

    expect(jwt).toEqual({ issuer: "https://identity.localhost", audience: "guard" });
  });

  test("a malformed cache TTL is a startup error, not a silent default", () => {
    for (const value of ["soon", "0", "-1", "1.5"]) {
      expect(() => runtimeOptions({ IDENTITY_JWKS_TTL_MS: value })).toThrow(RangeError);
    }
  });

  test("a typo'd issuer fails at startup rather than on every request", () => {
    // `identity.localhost` without a scheme is the mistake an operator makes,
    // and it would otherwise surface as a 503 on every call.
    expect(() => createApp(runtimeOptions({ IDENTITY_ISSUER: "identity.localhost" }))).toThrow(RangeError);
  });
});

describe("runtimeOptions: the BFF identity URL", () => {
  test("defaults to the local identity", () => {
    expect(runtimeOptions({}).bff?.identityUrl).toBe("http://localhost:8080");
  });

  test("IDENTITY_URL is the base URL the auth calls are built from", () => {
    // The issuer is where guard *verifies* tokens; this is where it *asks* for
    // sessions. They are the same service and two variables, because one is an
    // https origin in every environment and the other is a service address.
    expect(runtimeOptions({ IDENTITY_URL: "http://identity:8080" }).bff?.identityUrl).toBe("http://identity:8080");
  });

  test("an empty variable is unset, not a value", () => {
    expect(runtimeOptions({ IDENTITY_URL: "  " }).bff?.identityUrl).toBe("http://localhost:8080");
  });

  test("a malformed identity URL is a startup error", () => {
    expect(() => runtimeOptions({ IDENTITY_URL: "identity:8080" })).toThrow(RangeError);
  });

  test("identity is a registered readiness dependency, so /readyz names it", () => {
    // The /auth routes are unreachable without it, which is the one condition
    // the readiness endpoint exists to report.
    const { probes } = runtimeOptions({});

    expect(Object.keys(probes ?? {})).toContain("identity");
    expect(typeof probes?.identity).toBe("function");
  });

  test("the bff block carries the same fetch the probes would use, by construction", () => {
    // runtimeOptions cannot inject a fetch — it reads the environment — so a
    // configured app is the only place the two meet, and this pins that the
    // probe is built from the same options rather than a second parse.
    const options = runtimeOptions({ IDENTITY_URL: "http://identity:8080" });

    expect(options.probes?.identity).toBeDefined();
    expect(options.bff?.identityUrl).toBe("http://identity:8080");
  });
});

describe("runtimeOptions: the rate limiter", () => {
  test("the shipped table is the one the app enforces", () => {
    const limits = runtimeOptions({}).rateLimit?.limits;

    expect(limits?.default).toEqual(DEFAULT_LIMIT_TABLE.default);
    expect(limits?.routes?.["/auth/login"]).toEqual(DEFAULT_LIMIT_TABLE.routes?.["/auth/login"]);
  });

  test("RATE_LIMIT_REQUESTS overrides the general allowance only", () => {
    const limits = runtimeOptions({ RATE_LIMIT_REQUESTS: "42" }).rateLimit?.limits;

    expect(limits?.default.limit).toBe(42);
    // The auth-adjacent entries are not configuration in v0: a table that is
    // half environment and half code is a table where lowering `default` is
    // mistaken for having lowered the login limit too.
    expect(limits?.routes?.["/auth/login"]?.limit).toBe(DEFAULT_LIMIT_TABLE.routes?.["/auth/login"]?.limit);
  });

  test("an empty variable leaves the shipped allowance alone", () => {
    expect(runtimeOptions({ RATE_LIMIT_REQUESTS: "  " }).rateLimit?.limits?.default.limit).toBe(
      DEFAULT_LIMIT_TABLE.default.limit,
    );
  });

  test("a limit of zero is a startup error, not unlimited", () => {
    for (const value of ["0", "-1", "1.5", "soon"]) {
      expect(() => runtimeOptions({ RATE_LIMIT_REQUESTS: value })).toThrow(RangeError);
    }
  });

  test("TRUSTED_PROXIES is how much of X-Forwarded-For is believed, and zero is the default", () => {
    expect(runtimeOptions({}).rateLimit?.trustedProxies).toBe(0);
    expect(runtimeOptions({ TRUSTED_PROXIES: "2" }).rateLimit?.trustedProxies).toBe(2);
    expect(() => runtimeOptions({ TRUSTED_PROXIES: "-1" })).toThrow(RangeError);
  });

  test("no REDIS_URL means the in-memory store, which is the single-instance answer", () => {
    const options = runtimeOptions({});

    expect(options.rateLimit?.store).toBeUndefined();
    expect(Object.keys(options.probes ?? {})).not.toContain("redis");
  });

  test("REDIS_URL selects the Redis store and registers it as a readiness dependency", () => {
    const options = runtimeOptions({ REDIS_URL: "redis://redis:6379" });

    expect(options.rateLimit?.store).toBeDefined();
    expect(Object.keys(options.probes ?? {})).toContain("redis");
  });

  test("building the app with a REDIS_URL opens no socket", () => {
    // The connection is lazy, which is what keeps this test off the network and
    // keeps a Redis outage from being a refusal to boot. The URL is still parsed
    // eagerly, so a typo is still a startup error.
    expect(() => createApp(runtimeOptions({ REDIS_URL: "redis://127.0.0.1:6379" }))).not.toThrow();
    expect(() => createApp(runtimeOptions({ REDIS_URL: "redis//redis" }))).toThrow(RangeError);
    expect(() => createApp(runtimeOptions({ REDIS_URL: "http://redis:6379" }))).toThrow(RangeError);
  });
});

describe("the shipped per-route table, through the app", () => {
  // `rateLimit: {}` and nothing else: the shipped table, the in-memory store, no
  // trusted proxies, and a real clock. This is what a deployment that accepted
  // the defaults is running.
  const shipped = () => createApp({ jwt: { issuer: identity.issuer, audience: CLIENT_ID }, rateLimit: {} });

  test("the auth surface is named as its own policy and the API surface as another", async () => {
    const app = shipped();

    const me = await app.request("/v1/me", bearer(await token()));
    const login = await app.request("/auth/login", { method: "POST" });

    expect(me.headers.get("RateLimit-Policy")).toBe(
      `"${DEFAULT_LIMIT_TABLE.routes?.["/v1/"]?.policy}";q=${DEFAULT_LIMIT_TABLE.routes?.["/v1/"]?.limit};w=60`,
    );
    expect(login.headers.get("RateLimit-Policy")).toBe(
      `"${DEFAULT_LIMIT_TABLE.routes?.["/auth/login"]?.policy}";q=${DEFAULT_LIMIT_TABLE.routes?.["/auth/login"]?.limit};w=60`,
    );
  });

  test("a login attempt is throttled by the login policy, not the API one", async () => {
    const limit = DEFAULT_LIMIT_TABLE.routes?.["/auth/login"]?.limit ?? 0;
    const app = shipped();
    const attempt = () =>
      app.request("/auth/login", { method: "POST", headers: { origin: "https://console.cafaye.com" } });

    const statuses: number[] = [];
    for (let i = 0; i < limit + 1; i++) statuses.push((await attempt()).status);

    // The first `limit` are answered by whatever is behind the route — 404 here,
    // because no browser surface is configured — and the one after them is a 429
    // on the login policy alone. Had /auth/login drawn on the general API
    // allowance, ten attempts would not have been enough to be refused.
    expect(statuses.slice(0, limit).every((status) => status !== 429)).toBe(true);
    expect(statuses[limit]).toBe(429);
  });

  test("the API allowance is untouched by an exhausted login allowance", async () => {
    const app = shipped();
    const attempt = () =>
      app.request("/auth/login", { method: "POST", headers: { origin: "https://console.cafaye.com" } });

    for (let i = 0; i <= DEFAULT_LIMIT_TABLE.routes?.["/auth/login"]?.limit!; i++) await attempt();

    expect((await attempt()).status).toBe(429);
    // Different policy, different bucket: the general API allowance is a
    // different 600 and has not been touched.
    expect((await app.request("/v1/me", bearer(await token()))).status).toBe(200);
  });
});

describe("API keys through the app", () => {
  test("a key authenticates, and is limited under its account rather than its secret", async () => {
    const keys = memoryApiKeyStore();
    const app = createApp({
      jwt: { issuer: identity.issuer, audience: CLIENT_ID },
      rateLimit: { limits: strictTable(1) },
      apiKeys: { keys },
    });
    const auth = createApiKeyAuth({ keys });

    const first = await auth.issue({ accountId: "acc-1", scopes: [] });
    const second = await auth.issue({ accountId: "acc-2", scopes: [] });
    const asKey = (secret: string) => app.request("/v1/me", { headers: { authorization: `ApiKey ${secret}` } });

    expect((await asKey(first.key)).status).toBe(200);
    // A different account, so a different bucket: two keys do not share one
    // allowance, which is the whole point of keying on the account.
    expect((await asKey(second.key)).status).toBe(200);
    expect((await asKey(first.key)).status).toBe(429);
  });

  test("a revoked key is 401 on the next request, and the secret never comes back", async () => {
    const keys = memoryApiKeyStore();
    const app = createApp({ jwt: { issuer: identity.issuer, audience: CLIENT_ID }, apiKeys: { keys } });
    const auth = createApiKeyAuth({ keys });
    const issued = await auth.issue({ accountId: "acc-1", scopes: [] });
    const asKey = () => app.request("/v1/me", { headers: { authorization: `ApiKey ${issued.key}` } });

    expect((await asKey()).status).toBe(200);

    await keys.revoke(issued.id);

    const refused = await asKey();
    const body = await refused.text();

    expect(refused.status).toBe(401);
    expect(body).not.toContain(issued.key);
    expect(body).not.toContain(issued.key.slice(12));
    // What is kept is the hash, and the list is how an operator sees it.
    const [listed] = await keys.list("acc-1");
    expect(listed?.prefix).toBe(issued.prefix);
    expect(listed?.revokedAt).toBeGreaterThan(0);
  });

  test("a key and a token for the same account share one allowance", async () => {
    const keys = memoryApiKeyStore();
    const app = createApp({
      jwt: { issuer: identity.issuer, audience: CLIENT_ID },
      rateLimit: { limits: strictTable(1) },
      apiKeys: { keys },
    });
    const auth = createApiKeyAuth({ keys });
    const issued = await auth.issue({ accountId: ACCOUNT, scopes: [] });

    expect((await app.request("/v1/me", bearer(await token()))).status).toBe(200);
    const byKey = await app.request("/v1/me", { headers: { authorization: `ApiKey ${issued.key}` } });

    // Same account, one bucket: holding a second credential must not be a way to
    // double one's rate.
    expect(byKey.status).toBe(429);
  });

  test("an app with no key store refuses a key rather than ignoring it", async () => {
    const app = createApp({ jwt: { issuer: identity.issuer, audience: CLIENT_ID } });
    const auth = createApiKeyAuth({ keys: memoryApiKeyStore() });
    const issued = await auth.issue({ accountId: ACCOUNT, scopes: [] });

    // No gate mounted, so the key is not a credential and the request is
    // anonymous: the token gate answers 401 rather than the key gate answering
    // 200 for a key guard has never heard of.
    const res = await app.request("/v1/me", { headers: { authorization: `ApiKey ${issued.key}` } });

    expect(res.status).toBe(401);
  });
});
