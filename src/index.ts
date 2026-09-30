import { Hono } from "hono";
import type { Context } from "hono";
import { createJwtVerifier, DEFAULT_IDENTITY_ISSUER, type AuthEnv, type JwtOptions } from "./middleware/jwt";
import { rateLimit } from "./middleware/rateLimit";
import { createBffAuth, DEFAULT_IDENTITY_URL, identityProbe, type BffOptions } from "./bff/auth";
import type { Probe, ProbeStatus } from "./probe";

export type { Probe, ProbeStatus } from "./probe";

export type AppOptions = {
  /**
   * Readiness probes by dependency name. Nothing registers one by hand: the
   * first packet that gives guard a dependency registers it here and nowhere
   * else, which `runtimeOptions` does for identity.
   */
  probes?: Record<string, Probe>;
  /** Omit to run with no rate limiting at all. */
  rateLimit?: { limit: number; windowMs: number };
  /**
   * Omit and the gateway serves probes only: with no issuer there is nothing to
   * verify a token against, and an endpoint that would have to trust a token is
   * worse than an endpoint that is not there.
   */
  jwt?: JwtOptions;
  /**
   * Omit and there is no browser surface at all, for the same reason: with no
   * identity to ask there is no session to mint, and an endpoint that would have
   * to invent one is worse than an endpoint that is not there.
   */
  bff?: BffOptions;
};

/**
 * Liveness and readiness answer even when the limiter is exhausted: a throttled
 * probe is an orchestrator that cannot see a healthy process, and the restart
 * that follows is worse than the traffic it was protecting against.
 */
const PROBE_PATHS = new Set(["/healthz", "/readyz"]);

/** The audience guard accepts when nothing says otherwise: guard itself. */
const DEFAULT_CLIENT_ID = "guard";

/**
 * Builds the app. Exported, and the only entrypoint the tests use — importing
 * this module must never open a socket.
 */
export function createApp(options: AppOptions = {}): Hono<AuthEnv> {
  const app = new Hono<AuthEnv>();

  const limiter = options.rateLimit
    ? rateLimit({ ...options.rateLimit, keyGenerator: clientKey })
    : null;

  app.use("*", async (c, next) => {
    if (!limiter || PROBE_PATHS.has(new URL(c.req.url).pathname)) return next();
    return limiter(c, next);
  });

  // Liveness is unconditional and touches nothing. A dependency outage must not
  // get the process restarted out from under in-flight requests; that is
  // /readyz's job. Keep the split.
  app.get("/healthz", (c) => c.json({ status: "ok" }));

  app.get("/readyz", async (c) => {
    const deps: Record<string, ProbeStatus> = {};
    let ready = true;

    for (const [name, probe] of Object.entries(options.probes ?? {})) {
      const status = await runProbe(probe);
      deps[name] = status;
      if (status !== "ok") ready = false;
    }

    return c.json({ deps }, ready ? 200 : 503);
  });

  // Mounted on the prefix rather than per route: a new /v1 route is
  // authenticated unless someone deliberately does otherwise, and forgetting to
  // is not a failure mode this gateway should have.
  if (options.jwt) {
    const jwt = createJwtVerifier(options.jwt);
    app.use("/v1/*", jwt.requireJwt);

    // The route that proves the chain is wired: no behaviour of its own, and it
    // forwards nothing. It is here so a deployment can be checked end to end,
    // and the routing packet replaces it with real traffic.
    app.get("/v1/me", (c) => c.json(c.get("principal")));
  }

  // The browser surface. Mounted per route, not on the /auth/* prefix: the
  // same-origin gate is for requests that change something, and on the prefix it
  // would demand an Origin header from GET /auth/me, which has nothing to
  // protect. Every /auth route is traffic, so the limiter above already counts
  // it — including the ones this gate refuses, because a cross-site POST that
  // costs a request to reject is a cross-site POST worth rejecting.
  if (options.bff) {
    const bff = createBffAuth(options.bff);
    app.post("/auth/register", bff.requireSameOrigin, bff.register);
    app.post("/auth/login", bff.requireSameOrigin, bff.login);
    app.post("/auth/logout", bff.requireSameOrigin, bff.logout);
    app.get("/auth/me", bff.me);
  }

  app.notFound((c) => c.json({ error: "not_found", message: "no such route" }, 404));

  app.onError((error, c) => {
    // The message can carry a dependency host, a query, or a token; the caller
    // gets a flat 500 and the detail goes to the log.
    console.error("guard: unhandled error", error);
    return c.json({ error: "internal_error", message: "unexpected server error" }, 500);
  });

  return app;
}

/**
 * A dependency that throws, rejects, hangs or answers with anything but "ok" is
 * one unavailable dependency. None of those may take the process down:
 * reporting 503 is the entire contract of /readyz.
 */
async function runProbe(probe: Probe): Promise<ProbeStatus> {
  try {
    return (await probe()) === "ok" ? "ok" : "unavailable";
  } catch {
    return "unavailable";
  }
}

/**
 * v0 client identity: the first hop of the forwarding chain.
 *
 * TODO(guard-02): key on the socket peer address instead. This header is
 * chosen by the caller, so until the edge proxy sits in front of guard and
 * overwrites it, a client can mint a fresh allowance per request. It is
 * recorded here as a known hole rather than hidden behind a default nobody
 * reads.
 */
function clientKey(c: Context): string {
  return c.req.header("x-forwarded-for")?.split(",")[0]?.trim() || "anonymous";
}

/**
 * Reads the process configuration. The environment is read here and only here:
 * `createApp` takes its configuration as an argument, so a test can build two
 * differently configured apps in one process and no environment variable can
 * reach around it.
 *
 * An empty or whitespace-only variable counts as unset. `IDENTITY_ISSUER=` is
 * what an unset variable looks like in a compose file, and treating it as a
 * value would fail every request instead of using the default.
 */
export function runtimeOptions(env: Record<string, string | undefined> = Bun.env): AppOptions {
  const ttl = env.IDENTITY_JWKS_TTL_MS?.trim();

  // Built once and used twice. The app gets the options; the probe is built from
  // the same object, so /readyz and /auth cannot end up naming two different
  // identity services after one careless edit.
  const bff: BffOptions = { identityUrl: env.IDENTITY_URL?.trim() || DEFAULT_IDENTITY_URL };

  return {
    bff,
    // Every /auth route is unreachable without identity, which is the one thing
    // a readiness endpoint exists to report. Registered here and nowhere else.
    probes: { identity: identityProbe(bff) },
    jwt: {
      issuer: env.IDENTITY_ISSUER?.trim() || DEFAULT_IDENTITY_ISSUER,
      audience: env.GUARD_CLIENT_ID?.trim() || DEFAULT_CLIENT_ID,
      jwksUrl: env.IDENTITY_JWKS_URL?.trim() || undefined,
      jwksCacheTtlMs: ttl ? parseTtl(ttl) : undefined,
    },
  };
}

/**
 * Milliseconds, an integer of at least 1. Anything else is a startup error
 * rather than a silent default: `0` would mean "never cache", and a misspelt
 * value would quietly turn the gateway into one that calls identity on every
 * request.
 */
function parseTtl(value: string): number {
  const ttl = Number(value);
  if (!Number.isInteger(ttl) || ttl < 1) {
    throw new RangeError(`guard: IDENTITY_JWKS_TTL_MS must be an integer >= 1, got ${JSON.stringify(value)}`);
  }
  return ttl;
}

if (import.meta.main) {
  const port = Number(Bun.env.PORT ?? 8080);
  Bun.serve({ port, fetch: createApp(runtimeOptions()).fetch });
  console.log(`guard listening on :${port}`);
}
