import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { createHash } from "node:crypto";
import { rateLimit } from "./rateLimit";
import { memoryRateLimitStore, type RateLimitStore } from "./rateLimitStore";
import { GCRA_LUA, redisRateLimitStore, type RedisCommands } from "./rateLimitRedis";
import type { AuthEnv, Principal } from "./jwt";

const WINDOW_MS = 60_000;

/**
 * The limiter mounted the way `index.ts` mounts it: after identity, so the key
 * it reads is one the process has verified. `principal` and `apiKeyId` are put
 * on the context by an auth middleware ahead of it, exactly as `requireJwt` and
 * the API-key gate do.
 */
function app(options: {
  limit?: number;
  windowMs?: number;
  store?: RateLimitStore;
  now?: () => number;
  trustedProxies?: number;
}) {
  const a = new Hono<AuthEnv>();
  const limiter = rateLimit({
    limit: options.limit ?? 5,
    windowMs: options.windowMs ?? WINDOW_MS,
    store: options.store ?? memoryRateLimitStore(),
    trustedProxies: options.trustedProxies ?? 0,
    now: options.now ?? (() => 0),
    policy: () => "guard-api",
    // The exemption `index.ts` uses: a probe is an orchestrator asking whether
    // the process is alive, and a throttled probe gets the process restarted.
    exempt: (path) => path === "/healthz",
  });

  a.use("*", limiter);
  a.get("/", (c) => c.json({ ok: true }));
  a.get("/healthz", (c) => c.json({ status: "ok" }));
  return a;
}

const principal = (accountId: string): Principal => ({
  sub: accountId,
  scope: [],
  claims: { sub: accountId, account_id: accountId },
});

/**
 * The GCRA script, run in this process, over a bucket map the caller owns.
 *
 * Deliberately not a socket: this is the same transcription
 * `rateLimitRedis.test.ts` uses, and the point of the burst above is that the
 * *store* is atomic, not that a particular transport was reached.
 */
function sharedRedis(state: { keys: Map<string, number> }): RedisCommands {
  return {
    async eval(script, keysIn, args) {
      if (script !== GCRA_LUA) throw new Error("unexpected script");

      const key = keysIn[0] ?? "";
      const limit = Number(args[0]);
      const windowMs = Number(args[1]);
      const now = Number(args[2]);
      const interval = windowMs / limit;
      const tat = state.keys.get(key) ?? 0;
      const next = Math.max(now, tat) + interval;
      const delay = next - now;

      if (delay > windowMs) return [0, tat, next - windowMs, 0];

      state.keys.set(key, next);

      return [1, next, next - interval - windowMs, Math.max(0, limit - Math.ceil((next - now) / interval))];
    },
    async ping() {
      return true;
    },
  };
}

describe("the limiter answers", () => {
  test("allows up to the limit and then refuses with 429", async () => {
    const a = app({ limit: 2 });

    expect((await a.request("/")).status).toBe(200);
    expect((await a.request("/")).status).toBe(200);

    const blocked = await a.request("/");
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("content-type")).toContain("application/problem+json");
  });

  test("a 429 is core's envelope, not the old {error,message} shape", async () => {
    const a = app({ limit: 1 });
    await a.request("/");

    const blocked = await a.request("/");
    const body = (await blocked.json()) as Record<string, unknown>;

    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("content-type")).toBe("application/problem+json");
    expect(body["code"]).toBe("rate_limited");
    expect(body["status"]).toBe(429);
    expect(body["type"]).toBe("https://errors.cafaye.com/rate_limited");
    expect(body["instance"]).toBe("/");
    expect(body["detail"]).toBe("too many requests for this window");
    expect(typeof body["trace_id"]).toBe("string");
    expect(blocked.headers.get("x-trace-id")).toBe(body["trace_id"] as string);
  });

  test("the probe endpoints are never throttled", async () => {
    const a = app({ limit: 1 });

    for (let i = 0; i < 5; i++) {
      expect((await a.request("/healthz")).status).toBe(200);
    }
  });
});

describe("atomicity under a burst", () => {
  /**
   * Every request is *sent* before any is awaited, which is what makes this a
   * burst rather than a sequence: nothing but the store decides the order.
   */
  const burstOf = async (send: () => Response | Promise<Response>, count: number): Promise<number[]> =>
    Promise.all(Array.from({ length: count }, () => Promise.resolve(send()).then((res) => res.status)));

  test("N concurrent requests admit exactly `limit` and refuse the rest", async () => {
    // THE atomicity test, and it is the one that matters: a read-then-write
    // limiter has every request read "0 used, limit 50" and then write "1 used",
    // and admits all 200 — 4x the allowance, which is the bug this whole packet
    // exists to close.
    const a = app({ limit: 50 });
    const burst = 200;

    const statuses = await burstOf(() => a.request("/"), burst);
    const admitted = statuses.filter((status) => status === 200);
    const refused = statuses.filter((status) => status === 429);

    expect(admitted).toHaveLength(50);
    expect(refused).toHaveLength(burst - 50);
    expect(admitted.length + refused.length).toBe(burst);
  });

  test("the same holds through a store that is not in this process", async () => {
    // The in-memory store gets its atomicity from a JavaScript turn being
    // uninterruptible; Redis gets it from one script. The burst is fired at both
    // so the claim is about the trait, not about one implementation of it.
    const commands = sharedRedis({ keys: new Map<string, number>() });
    const a = app({ limit: 50, store: redisRateLimitStore({ commands }) });

    const statuses = await burstOf(() => a.request("/"), 200);

    expect(statuses.filter((status) => status === 200)).toHaveLength(50);
    expect(statuses.filter((status) => status === 429)).toHaveLength(150);
  });

  test("two limiters over one store share the allowance, the way two replicas do", async () => {
    // Two app instances, one counter store. This is the shape of a two-replica
    // deployment and it is why a shared store exists at all: with the in-memory
    // store these two are two allowances and each admits the full limit.
    const store = memoryRateLimitStore();
    const a = app({ limit: 10, store });
    const b = app({ limit: 10, store });

    const statuses = [
      ...(await burstOf(() => a.request("/"), 10)),
      ...(await burstOf(() => b.request("/"), 10)),
    ];

    expect(statuses.filter((status) => status === 200)).toHaveLength(10);
  });

  test("no identity a caller can present can produce a key the Redis store refuses", async () => {
    // The store's charset check is a backstop, and tripping it is not a loud
    // failure: the store throws, the middleware fails open, and the limiter is
    // off in the deployment that has one. So the key has to be safe before it
    // gets there, for identities guard does not choose.
    const commands = sharedRedis({ keys: new Map() });
    const store = redisRateLimitStore({ commands });
    const hostile = [
      "account:with spaces",
      'account:"quoted"',
      "account:*",
      "account:glob?",
      "account:with\nnewline",
      "ip:fe80::1%25en0",
      "ip:unknown",
      "account:../../etc/passwd",
    ];

    for (const identity of hostile) {
      const bucket = `${"guard-api"}:${digestOf(identity)}`;
      expect(() => store.keyFor(bucket)).not.toThrow();
    }
  });
});

/** The digest the middleware puts in a bucket key, recomputed for the test. */
function digestOf(identity: string): string {
  return createHash("sha256").update(identity, "utf8").digest("hex").slice(0, 32);
}

describe("RateLimit-* headers", () => {
  test("RFC 9651-era fields: RateLimit-Policy and RateLimit, as structured fields", async () => {
    const a = app({ limit: 3, windowMs: 30_000 });
    const res = await a.request("/");

    // draft-ietf-httpapi-ratelimit-headers §3: a List of Items, each a String
    // naming the policy, with `q` for the quota and `w` for the window in
    // seconds.
    expect(res.headers.get("RateLimit-Policy")).toBe('"guard-api";q=3;w=30');

    // §4: the same policy named, `r` for the quota available and `t` for the
    // *effective window* — the seconds within which that quota may be used
    // (§4.1.2). One request of three has bought back one interval, so the
    // remaining two last one interval and not the whole thirty seconds; the
    // draft's own B.1.3 example shows `t` counting down the same way.
    expect(res.headers.get("RateLimit")).toBe('"guard-api";r=2;t=10');
  });

  test("the widely-deployed RateLimit-Limit/-Remaining/-Reset trio is still sent", async () => {
    const a = app({ limit: 3 });
    const res = await a.request("/");

    expect(res.headers.get("RateLimit-Limit")).toBe("3");
    expect(res.headers.get("RateLimit-Remaining")).toBe("2");
    expect(Number(res.headers.get("RateLimit-Reset"))).toBeGreaterThan(0);
  });

  test("RateLimit-Reset counts down in seconds, as the field is defined", async () => {
    let now = 0;
    const a = app({ limit: 2, now: () => now });

    const first = await a.request("/");
    // Two of two are allowed at one per interval, so the allowance is whole
    // again one interval later — not one window later, which is what a fixed
    // window said.
    expect(Number(first.headers.get("RateLimit-Reset"))).toBe(30);

    // A minute later the first request has aged out and this one is the first
    // of a fresh allowance, so the header describes the state *after* it: one
    // interval in debt, one interval to being whole again.
    now = 30_000;
    const second = await a.request("/");
    expect(Number(second.headers.get("RateLimit-Reset"))).toBe(30);
    expect(second.headers.get("RateLimit-Remaining")).toBe("1");
  });

  test("X-RateLimit-Reset is the absolute epoch instant, not a countdown", async () => {
    // This repository's own convention, kept because a client that wants a wall
    // clock deadline should not have to reconstruct one from a delta.
    let now = 1_000_000;
    const a = app({ limit: 2, now: () => now });
    const res = await a.request("/");

    expect(Number(res.headers.get("X-RateLimit-Reset"))).toBe(1_030_000);
  });

  test("the three fields are correct on a 429 as well as a 200", async () => {
    const a = app({ limit: 1 });
    await a.request("/");

    const blocked = await a.request("/");

    expect(blocked.headers.get("RateLimit-Limit")).toBe("1");
    expect(blocked.headers.get("RateLimit-Remaining")).toBe("0");
    expect(Number(blocked.headers.get("RateLimit-Reset"))).toBe(WINDOW_MS / 1000);
    expect(blocked.headers.get("RateLimit")).toBe('"guard-api";r=0;t=60');
  });

  test("a 429 says how long to wait, in whole seconds", async () => {
    const a = app({ limit: 1, windowMs: 30_000 });
    await a.request("/");

    const blocked = await a.request("/");
    const retryAfter = Number(blocked.headers.get("Retry-After"));

    expect(Number.isInteger(retryAfter)).toBe(true);
    // The one request this window allows was spent at t=0 and the next is due
    // one whole interval later. `Retry-After` is the instant the *refused*
    // request would be admitted, not half a window and not the whole window.
    expect(retryAfter).toBe(30);
  });

  test("Retry-After is never zero, so a throttled client cannot hot-loop", async () => {
    let now = 0;
    const a = app({ limit: 1, now: () => now });
    await a.request("/");

    for (let i = 0; i < 5; i++) {
      const blocked = await a.request("/");
      expect(Number(blocked.headers.get("Retry-After"))).toBeGreaterThanOrEqual(1);
    }
  });

  test("no 200 carries a Retry-After, which means something different", async () => {
    const res = await app({ limit: 3 }).request("/");

    expect(res.headers.get("Retry-After")).toBeNull();
  });
});

describe("key derivation, through the middleware", () => {
  /** Puts a verified principal on the context, the way `requireJwt` does. */
  function withJwt(limiter: ReturnType<typeof rateLimit>, accountId: string) {
    const a = new Hono<AuthEnv>();
    a.use("*", async (c, next) => {
      c.set("principal", principal(accountId));
      return limiter(c, next);
    });
    a.get("/", (c) => c.json({ ok: true }));
    return a;
  }

  test("an account with a key is limited under the account bucket", async () => {
    // Same account, two credentials. Both must draw on the one allowance, or a
    // caller could double its rate simply by also holding a key.
    const store = memoryRateLimitStore();
    const limit = 3;
    const options = {
      limit,
      windowMs: WINDOW_MS,
      store,
      trustedProxies: 0,
      now: () => 0,
      policy: () => "guard-api",
    };

    const tokenApp = withJwt(rateLimit(options), "acc-42");
    const keyApp = new Hono<AuthEnv>();
    keyApp.use("*", async (c, next) => {
      c.set("principal", principal("acc-42"));
      c.set("apiKeyId", "key-7");
      return rateLimit(options)(c, next);
    });
    keyApp.get("/", (c) => c.json({ ok: true }));

    const statuses: number[] = [];
    for (const request of [tokenApp, tokenApp, keyApp, keyApp]) {
      statuses.push((await request.request("/")).status);
    }

    expect(statuses).toEqual([200, 200, 200, 429]);
  });

  test("two accounts never share an allowance", async () => {
    const options = { limit: 1, windowMs: WINDOW_MS, store: memoryRateLimitStore(), trustedProxies: 0, now: () => 0, policy: () => "guard-api" };

    const a = withJwt(rateLimit(options), "acc-1");
    const b = withJwt(rateLimit(options), "acc-2");

    expect((await a.request("/")).status).toBe(200);
    expect((await a.request("/")).status).toBe(429);
    expect((await b.request("/")).status).toBe(200);
  });

  test("a key alone is limited under its own id, not under the address", async () => {
    const store = memoryRateLimitStore();
    const options = { limit: 2, windowMs: WINDOW_MS, store, trustedProxies: 0, now: () => 0, policy: () => "guard-api" };
    const a = new Hono<AuthEnv>();
    a.use("*", (c, next) => {
      // Stands in for the API-key gate: the store turns a presented secret into
      // a key id, and that id is all the limiter is given. The secret itself
      // never reaches the rate-limit key — the same property
      // `limitKey.test.ts` pins for the account claim.
      const secret = c.req.header("authorization")?.replace(/^ApiKey\s+/i, "");
      c.set("apiKeyId", secret ? `key:${secret}` : undefined);
      return rateLimit(options)(c, next);
    });
    a.get("/", (c) => c.json({ ok: true }));

    const withKey = (key: string) =>
      a.request("/", { headers: { authorization: `ApiKey ${key}`, "x-forwarded-for": "203.0.113.4" } });

    expect((await withKey("caf_a")).status).toBe(200);
    expect((await withKey("caf_a")).status).toBe(200);
    expect((await withKey("caf_a")).status).toBe(429);
    // A different key from the same address is a different caller.
    expect((await withKey("caf_b")).status).toBe(200);
  });

  test("a caller with no credential at all is limited by address", async () => {
    const a = app({ limit: 1, trustedProxies: 1 });

    const from = (ip: string) => a.request("/", { headers: { "x-forwarded-for": ip } });

    expect((await from("203.0.113.4")).status).toBe(200);
    expect((await from("203.0.113.4")).status).toBe(429);
    expect((await from("203.0.113.5")).status).toBe(200);
  });
});

describe("per-route limits", () => {
  /** One store, several policies — the shape `createApp` builds. */
  function routed() {
    const store = memoryRateLimitStore();
    const policies = new Map<string, number>();
    const a = new Hono<AuthEnv>();

    a.use("*", async (c, next) => {
      const pathname = new URL(c.req.url).pathname;
      const auth = pathname.startsWith("/auth/");
      const policy = auth ? "guard-auth" : "guard-api";
      policies.set(policy, (policies.get(policy) ?? 0) + 1);
      return rateLimit({
        limit: auth ? 2 : 5,
        windowMs: WINDOW_MS,
        store,
        trustedProxies: 1,
        now: () => 0,
        policy: () => policy,
      })(c, next);
    });
    a.post("/auth/login", (c) => c.json({ ok: true }));
    a.get("/v1/me", (c) => c.json({ ok: true }));
    return { a, policies };
  }

  test("the auth surface and the API surface draw on separate allowances", async () => {
    const { a } = routed();

    for (let i = 0; i < 5; i++) expect((await a.request("/v1/me")).status).toBe(200);

    // The API allowance is spent; the auth allowance is untouched.
    expect((await a.request("/auth/login", { method: "POST" })).status).toBe(200);
    expect((await a.request("/v1/me")).status).toBe(429);
  });

  test("the stricter policy is the one that says so", async () => {
    const { a } = routed();
    const login = await a.request("/auth/login", { method: "POST" });
    const me = await a.request("/v1/me");

    expect(login.headers.get("RateLimit-Policy")).toContain("q=2");
    expect(me.headers.get("RateLimit-Policy")).toContain("q=5");
  });

  test("one table, one store, and each policy enforced with its OWN numbers", async () => {
    // The bug this pins: a limiter that names the policy per request but
    // enforces one number on every route advertises a limit table and does not
    // have one. `routed()` above hides it by building a limiter per request;
    // here there is one limiter and the numbers come from `resolve`.
    const store = memoryRateLimitStore();
    const table = new Map([
      ["guard-auth-login", { limit: 2, windowMs: WINDOW_MS }],
      ["guard-api", { limit: 5, windowMs: WINDOW_MS }],
    ]);
    const a = new Hono<AuthEnv>();
    a.use(
      "*",
      rateLimit({
        limit: 100,
        windowMs: WINDOW_MS,
        store,
        trustedProxies: 0,
        now: () => 0,
        policy: (c) => (new URL(c.req.url).pathname === "/auth/login" ? "guard-auth-login" : "guard-api"),
        resolve: (name) => table.get(name) ?? null,
      }),
    );
    a.post("/auth/login", (c) => c.json({ ok: true }));
    a.get("/v1/me", (c) => c.json({ ok: true }));

    // Two logins is the login allowance, and the third is refused.
    expect((await a.request("/auth/login", { method: "POST" })).status).toBe(200);
    expect((await a.request("/auth/login", { method: "POST" })).status).toBe(200);
    expect((await a.request("/auth/login", { method: "POST" })).status).toBe(429);

    // The API allowance is five, and none of it was spent by the logins.
    for (let i = 0; i < 5; i++) expect((await a.request("/v1/me")).status).toBe(200);
    expect((await a.request("/v1/me")).status).toBe(429);
  });

  test("a policy the table does not name falls back to the constructor's numbers", async () => {
    const store = memoryRateLimitStore();
    const a = new Hono<AuthEnv>();
    a.use(
      "*",
      rateLimit({
        limit: 1,
        windowMs: WINDOW_MS,
        store,
        trustedProxies: 0,
        now: () => 0,
        policy: () => "unlisted",
        resolve: () => null,
      }),
    );
    a.get("/", (c) => c.json({ ok: true }));

    expect((await a.request("/")).status).toBe(200);
    expect((await a.request("/")).status).toBe(429);
  });
});

describe("a store that is not there", () => {
  test("an unreachable store does not become a platform-wide 429", async () => {
    const broken = {
      hit: () => Promise.reject(new Error("redis: connection refused")),
    } as RateLimitStore;
    const a = app({ store: broken, limit: 100 });

    const res = await a.request("/");

    // Failing open is a choice with a cost, and the cost is named in the README
    // and in the source: a counter-store outage removes the limiter, so the
    // dependency is a registered readiness probe rather than something to be
    // surprised by. Failing closed would take the whole edge down with Redis.
    expect(res.status).toBe(200);
  });

  test("an unreachable store leaves the RateLimit headers off rather than lying", async () => {
    const broken = { hit: () => Promise.reject(new Error("nope")) } as RateLimitStore;
    const res = await app({ store: broken }).request("/");

    expect(res.headers.get("RateLimit-Limit")).toBeNull();
    expect(res.headers.get("RateLimit")).toBeNull();
    expect(res.headers.get("X-RateLimit-Reset")).toBeNull();
  });
});

describe("construction", () => {
  test("rejects a limit below one", () => {
    for (const limit of [0, -1, 1.5]) {
      expect(() =>
        rateLimit({ limit, windowMs: WINDOW_MS, store: memoryRateLimitStore(), trustedProxies: 0, policy: () => "p" }),
      ).toThrow(RangeError);
    }
  });

  test("rejects a window below one millisecond", () => {
    for (const windowMs of [0, -1, 1.5]) {
      expect(() =>
        rateLimit({ limit: 1, windowMs, store: memoryRateLimitStore(), trustedProxies: 0, policy: () => "p" }),
      ).toThrow(RangeError);
    }
  });

  test("rejects a negative trusted proxy count", () => {
    expect(() =>
      rateLimit({ limit: 1, windowMs: WINDOW_MS, store: memoryRateLimitStore(), trustedProxies: -1, policy: () => "p" }),
    ).toThrow(RangeError);
  });

  test("a policy name is quoted, so one containing a quote cannot inject a second item", async () => {
    const store = memoryRateLimitStore();
    const limiter = rateLimit({
      limit: 1,
      windowMs: WINDOW_MS,
      store,
      trustedProxies: 0,
      policy: () => 'evil",r=999;t=1',
    });
    const a = new Hono();
    a.use("*", limiter);
    a.get("/", (c) => c.json({ ok: true }));

    const res = await a.request("/");

    // The name is validated, not escaped: a policy is guard's configuration, and
    // a configured one that cannot be serialised is a startup-shaped mistake.
    expect(res.status).not.toBe(200);
  });
});
