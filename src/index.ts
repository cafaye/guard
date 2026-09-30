import { Hono } from "hono";
import type { Context } from "hono";
import { createJwtVerifier, DEFAULT_IDENTITY_ISSUER, type AuthEnv, type JwtOptions } from "./middleware/jwt";
import { rateLimit, type RateLimitOptions } from "./middleware/rateLimit";
import { memoryRateLimitStore } from "./middleware/rateLimitStore";
import type { RateLimitStore } from "./middleware/rateLimitTypes";
import { lazyRedis, redisRateLimitStore, type RedisCommands } from "./middleware/rateLimitRedis";
import { createApiKeyAuth, type ApiKeyStore } from "./middleware/apiKey";
import { DEFAULT_LIMIT_TABLE, limitTable, resolveLimit, type LimitTable } from "./middleware/limits";
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
  /**
   * The rate limiter, or nothing. Omitted means the gateway applies no limit at
   * all, which is the honest v0 default for an app built without one rather than
   * a limit that exists only in the config.
   *
   * `limits` is the per-route table; `store` is where buckets are counted. Both
   * are arguments rather than environment reads so a test can build two
   * differently configured apps in one process, and so a test never has to be near
   * a Redis to exercise the limiter.
   */
  rateLimit?: {
    limits?: LimitTable;
    store?: RateLimitStore;
    /** How many proxies may append to `X-Forwarded-For`. Zero believes none. */
    trustedProxies?: number;
    /** Clock, injected so a test can cross a window boundary without sleeping. */
    now?: () => number;
  };
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
  /**
   * API keys. Omit and no request may authenticate with one, which is the right
   * default for a deployment that has not decided where keys are stored.
   */
  apiKeys?: { keys: ApiKeyStore };
};

/**
 * Liveness and readiness answer even when the limiter is exhausted: a throttled
 * probe is an orchestrator that cannot see a healthy process, and the restart
 * that follows is worse than the traffic it was protecting against.
 *
 * Exported because the OpenAPI document's `429` story depends on it: those two
 * operations are the only ones in `openapi/v1.yaml` with no `429`, and that is a
 * claim about *this* set rather than a list somebody typed into a YAML file.
 */
export const PROBE_PATHS = new Set(["/healthz", "/readyz"]);

/** The audience guard accepts when nothing says otherwise: guard itself. */
const DEFAULT_CLIENT_ID = "guard";

/**
 * Builds the app. Exported, and the only entrypoint the tests use — importing
 * this module must never open a socket.
 */
export function createApp(options: AppOptions = {}): Hono<AuthEnv> {
  const app = new Hono<AuthEnv>();

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

  // The API-key gate comes first and covers `*`, so a key works on any route a
  // token would work on rather than only on the ones someone remembered to
  // extend. It is conditional: a request with no key is somebody else's problem
  // and falls through to the token gate below.
  //
  // Mounted BEFORE the limiter, and that ordering is the whole point of the
  // packet: the bucket is keyed on the account, and the account is only known
  // once something has proved who is asking. A token that does not verify never
  // reaches the limiter at all, so an unverified claim can never become a
  // rate-limit key.
  if (options.apiKeys) {
    const keys = createApiKeyAuth(options.apiKeys);
    app.use("*", async (c, next) => {
      if (!keys.hasKeyScheme(c)) return next();

      return keys.authenticate(c, next);
    });
  }

  // Mounted on the prefix rather than per route: a new /v1 route is
  // authenticated unless someone deliberately does otherwise, and forgetting to
  // is not a failure mode this gateway should have. A key that authenticated
  // above already has a principal, so it passes straight through.
  //
  // The route itself is registered further down, after the limiter, and that
  // ordering is not cosmetic: Hono matches handlers in registration order and a
  // route registered before a `use` answers first and never calls `next`. A
  // limiter mounted after a route is a limiter that does not run.
  const jwt = options.jwt ? createJwtVerifier(options.jwt) : null;
  if (jwt) {
    app.use("/v1/*", async (c, next) => {
      if (c.get("principal")) return next();

      return jwt.requireJwt(c, next);
    });
  }

  // The limiter, after authentication and therefore after the identity is
  // known. Every /auth route is traffic and is counted by this too, including the
  // ones the same-origin gate refuses: a cross-site POST that costs a request to
  // reject is a cross-site POST worth rejecting. The probe endpoints are exempt
  // and no other path is — and they are exempt by name here rather than by being
  // registered before this, because "registered earlier" is not a limiter.
  const limiter = buildLimiter(options.rateLimit);
  if (limiter) {
    app.use("*", async (c, next) => limiter(c, next));
  }

  if (jwt) {
    // The route that proves the chain is wired: no behaviour of its own, and it
    // forwards nothing. It is here so a deployment can be checked end to end,
    // and the routing packet replaces it with real traffic.
    app.get("/v1/me", (c) => c.json(c.get("principal")));
  }

  // The browser surface. Mounted per route, not on the /auth/* prefix: the
  // same-origin gate is for requests that change something, and on the prefix it
  // would demand an Origin header from GET /auth/me, which has nothing to
  // protect.
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
 * The limiter, or null when the app was built without one.
 *
 * The policy is read per request off the limit table, which is why the
 * auth-adjacent routes are stricter than the API surface without either of them
 * knowing about the other. The store defaults to the in-memory one, which is
 * correct for a single instance and is documented as such: N replicas of an
 * in-memory limiter is an N-times limit. `runtimeOptions` passes a Redis store
 * whenever `REDIS_URL` is set.
 */
function buildLimiter(config: AppOptions["rateLimit"]) {
  if (!config) return null;

  const table = limitTable(config.limits ?? DEFAULT_LIMIT_TABLE);
  // Policy name -> that policy's own numbers, with `default` first so a route
  // entry that reuses the default policy name inherits its own entry. This is
  // the map that makes a per-route table's *numbers* per-route; without it every
  // route would be enforced with the default's limit and only the header would
  // differ, which is a limit table that looks configured and is not.
  const byPolicy = new Map<string, { limit: number; windowMs: number }>();
  for (const entry of [table.default, ...Object.values(table.routes ?? {})]) {
    byPolicy.set(entry.policy, { limit: entry.limit, windowMs: entry.windowMs });
  }

  const options: RateLimitOptions = {
    limit: table.default.limit,
    windowMs: table.default.windowMs,
    store: config.store ?? memoryRateLimitStore(),
    trustedProxies: config.trustedProxies ?? 0,
    now: config.now ?? Date.now,
    exempt: (path) => PROBE_PATHS.has(path),
    policy: (c) => policyOf(c, table),
    resolve: (name) => byPolicy.get(name) ?? null,
  };

  return rateLimit(options);
}

/** The policy in force for one request, which is also half its bucket key. */
function policyOf(c: Context, table: LimitTable): string {
  return resolveLimit(table, new URL(c.req.url).pathname).policy;
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
  const redis = redisFromEnv(env);

  return {
    bff,
    // Every /auth route is unreachable without identity, which is the one thing
    // a readiness endpoint exists to report. Registered here and nowhere else.
    probes: { identity: identityProbe(bff), ...(redis ? { redis: redis.probe } : {}) },
    jwt: {
      issuer: env.IDENTITY_ISSUER?.trim() || DEFAULT_IDENTITY_ISSUER,
      audience: env.GUARD_CLIENT_ID?.trim() || DEFAULT_CLIENT_ID,
      jwksUrl: env.IDENTITY_JWKS_URL?.trim() || undefined,
      jwksCacheTtlMs: ttl ? parseTtl(ttl) : undefined,
    },
    rateLimit: {
      limits: limitTable({
        // The shipped default, with the general allowance overridable. The
        // per-route entries are NOT overridable from the environment in v0: a
        // table that is half configuration and half code is a table where an
        // operator can lower `default` and believe they have, without having.
        default: {
          limit: wholeNumber(env.RATE_LIMIT_REQUESTS, DEFAULT_LIMIT_TABLE.default.limit, "RATE_LIMIT_REQUESTS", 1),
          windowMs: wholeNumber(env.RATE_LIMIT_WINDOW_MS, DEFAULT_LIMIT_TABLE.default.windowMs, "RATE_LIMIT_WINDOW_MS", 1),
          policy: DEFAULT_LIMIT_TABLE.default.policy,
        },
        routes: DEFAULT_LIMIT_TABLE.routes ?? {},
      }),
      trustedProxies: wholeNumber(env.TRUSTED_PROXIES, 0, "TRUSTED_PROXIES", 0),
      // A Redis URL is the operator saying there is more than one replica, and
      // the counter has to be shared or the limit is multiplied by the replica
      // count. Without one the in-memory store is the honest answer for a single
      // instance, and it says so in its own source and in the README.
      ...(redis ? { store: redisRateLimitStore({ commands: redis.commands, prefix: redis.prefix }) } : {}),
    },
  };
}

type RedisConfig = { commands: RedisCommands; prefix: string | undefined; probe: Probe };

/**
 * The counter store's connection and its readiness probe, or nothing.
 *
 * Returned as one value so `/readyz` cannot end up reporting a store the limiter
 * is not using: the probe and the store are built from the same connection here,
 * once. `lazyRedis` opens the socket on first use rather than here, so a typo'd
 * URL is still a startup error and a *down* Redis is not a refusal to boot.
 */
function redisFromEnv(env: Record<string, string | undefined>): RedisConfig | null {
  const url = env.REDIS_URL?.trim();
  if (!url) return null;

  const commands = lazyRedis({ url });
  const probe: Probe = async (): Promise<ProbeStatus> => {
    try {
      return (await commands.ping()) ? "ok" : "unavailable";
    } catch {
      return "unavailable";
    }
  };

  return { commands, prefix: env.REDIS_PREFIX?.trim() || undefined, probe };
}

/**
 * An integer from the environment, validated.
 *
 * `RATE_LIMIT_REQUESTS=0` is a refusal to boot and not "unlimited", and a
 * misspelt value is a startup error rather than a silent default that throttles
 * nobody. An unset or empty variable leaves the shipped value alone, because an
 * empty variable is what an unset one looks like in a compose file.
 */
function wholeNumber(raw: string | undefined, fallback: number, field: string, lowest: number): number {
  const value = raw?.trim();
  if (value === undefined || value === "") return fallback;

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < lowest) {
    throw new RangeError(`guard: ${field} must be an integer >= ${lowest}, got ${JSON.stringify(value)}`);
  }

  return parsed;
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

if (import.meta.main) {
  const port = Number(Bun.env.PORT ?? 8080);
  Bun.serve({ port, fetch: createApp(runtimeOptions()).fetch });
  console.log(`guard listening on :${port}`);
}
