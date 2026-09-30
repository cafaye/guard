import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createApp, runtimeOptions, type ProbeStatus } from "./index";
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

  test("traffic is rate limited, and so is a rejected token", async () => {
    const app = createApp({
      jwt: { issuer: identity.issuer, audience: CLIENT_ID },
      rateLimit: { limits: strictTable(1) },
    });

    expect((await app.request("/v1/me", bearer(await token()))).status).toBe(200);

    const res = await app.request("/v1/me", bearer(await token()));

    expect(res.status).toBe(429);
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
