// The rate-limit middleware.
//
// Everything about *which* bucket a request belongs to is `./limitKey`, and
// everything about *how* a bucket is counted is `./rateLimitStore` behind
// `RateLimitStore`. What is left here is the part only this file can decide:
//
//   * the key, read from the verified identity and never from a header,
//   * the policy, which is half the key and the name in `RateLimit-Policy`,
//   * what a client is told — RFC 9651's `RateLimit-Policy` and `RateLimit`, the
//     `RateLimit-Limit`/`-Remaining`/`-Reset` trio every deployed client
//     already reads, and `Retry-After` on a refusal,
//   * and what happens when the counter store is unreachable.
//
// It is mounted AFTER authentication, on purpose. The key is the strongest
// identity the request has, and the strongest identity is only known once a token
// has been verified or a key has been looked up. The cost of that ordering is
// stated rather than hidden: a request refused by the auth gate is never counted,
// because a token that does not verify must not become a rate-limit key, and a
// rejected credential is cheap to reject — the algorithm is read off the header
// before any key is fetched.
import type { Context, MiddlewareHandler } from "hono";
import { createHash } from "node:crypto";
import { problem, type Problem } from "../problem";
import { assertNonNegativeInteger, assertPositiveInteger, assertStructuredKey } from "./assert";
import { keySourceOf, rateLimitKey } from "./limitKey";
import type { AuthEnv } from "./jwt";
import type { RateLimitStore } from "./rateLimitTypes";

export type RateLimitOptions = {
  /** Requests allowed per window. An integer >= 1. */
  limit: number;
  /** Window length in milliseconds. An integer >= 1. */
  windowMs: number;
  /** Where buckets are counted. See `./rateLimitStore` for the two of them. */
  store: RateLimitStore;
  /**
   * How many proxies stand in front of guard, which is how much of
   * `X-Forwarded-For` may be believed. Zero — the default — believes none of
   * it. See `./limitKey`.
   */
  trustedProxies?: number;
  /**
   * The policy in force for this request, which is half the counter key and the
   * name in `RateLimit-Policy`. A function, because it is read per request: a
   * per-route table cannot be resolved once at construction.
   */
  policy: (c: Context) => string;
  /**
   * The numbers a policy name stands for, when a route carries its own.
   *
   * `limit` and `windowMs` above are the allowance for a policy this table does
   * not name, which is the common case: one gateway, one allowance. When a
   * deployment ships a per-route table, this is how the stricter entries get
   * their own numbers instead of inheriting the default's — the policy name is
   * the key, and a name the table does not carry falls back rather than failing,
   * so a typo in a table costs the default allowance and nothing else.
   */
  resolve?: (policy: string) => { limit: number; windowMs: number } | null;
  /** Clock, injected so a test can cross a window boundary without sleeping. */
  now?: () => number;
  /** Paths that are never throttled. See `index.ts` for the probe endpoints. */
  exempt?: (path: string) => boolean;
};

/**
 * The sliding-window limiter.
 *
 * `store.hit` is the whole decision: it counts and answers in one atomic step, so
 * a burst of N concurrent requests admits exactly `limit` of them rather than N.
 * There is no read here before the write, and that is the property the burst test
 * in `rateLimit.test.ts` exists to hold in place.
 */
export function rateLimit(options: RateLimitOptions): MiddlewareHandler<AuthEnv> {
  const { store, policy, now = Date.now, exempt = () => false, resolve } = options;
  const trustedProxies = options.trustedProxies ?? 0;
  const limits = new Map<string, { limit: number; windowMs: number; policy: string }>();

  // At construction, so `RATE_LIMIT_REQUESTS=0` is a refusal to boot rather than
  // a surprise on the first request of the week.
  assertPositiveInteger(options.limit, "limit");
  assertPositiveInteger(options.windowMs, "windowMs");
  assertNonNegativeInteger(trustedProxies, "trustedProxies");

  // The policy name is validated per distinct name rather than once, because a
  // policy is read per request and only the names a request actually asks for can
  // be checked. It is validated, not escaped: a name that cannot be serialised
  // into a structured field is a configuration mistake to surface, and the one
  // way it could be *not* surfaced is a header carrying a second field item that
  // a client reads as a second policy.
  //
  // The numbers come from the table when it has an entry for the name, and from
  // the constructor otherwise — so one gateway with one allowance needs no table
  // at all, and a gateway with a per-route table gets each entry's own numbers
  // rather than the default's on every route.
  const allow = (name: string): { limit: number; windowMs: number; policy: string } => {
    const known = limits.get(name);
    if (known) return known;

    const entry = resolve?.(name);
    if (entry) {
      assertPositiveInteger(entry.limit, `policy ${name}: limit`);
      assertPositiveInteger(entry.windowMs, `policy ${name}: windowMs`);
    }

    const checked = {
      limit: entry?.limit ?? options.limit,
      windowMs: entry?.windowMs ?? options.windowMs,
      policy: assertStructuredKey(name, "policy"),
    };
    limits.set(name, checked);

    return checked;
  };

  return async function rateLimitMiddleware(c, next) {
    const at = now();
    if (exempt(new URL(c.req.url).pathname)) return next();

    const active = allow(policy(c));
    const key = rateLimitKey(keySourceOf(c, trustedProxies));

    let verdict: Awaited<ReturnType<RateLimitStore["hit"]>>;
    try {
      verdict = await store.hit(bucket(active.policy, key), {
        limit: active.limit,
        windowMs: active.windowMs,
        now: at,
      });
    } catch (error) {
      return failedOpen(error, next);
    }

    announce(c, active, verdict, at);

    if (!verdict.allowed) {
      // A whole second at minimum. `Retry-After: 0` tells a client to come back
      // immediately, and a client that obeys it is a hot loop against a bucket
      // that cannot open for another few hundred milliseconds.
      c.header("Retry-After", String(Math.max(1, Math.ceil((verdict.retryAt - at) / 1000))));
      return problem(c, throttled());
    }

    await next();
  };
}

/**
 * The counter key: the policy, then a digest of the caller's identity.
 *
 * The policy leads it, so two policies never share a bucket by accident and a
 * caller who exhausts /auth/login cannot spend the /v1 allowance.
 *
 * The identity is digested rather than pasted in, and that is not
 * tidiness. `rateLimitKey` produces whatever the verified identity contains: an
 * `account_id` claim is whatever identity chose to put there, an IPv6 address can
 * carry a `%zone`, and a bucket name becomes a Redis key. The store's charset
 * check exists to stop anything unsafe landing in one — and a key that trips it
 * throws, the middleware fails open, and the limiter is silently off in exactly
 * the deployment that needs it. Hashing makes that impossible by construction
 * rather than by a charset nobody remembers, and it has the side benefit the
 * rate-limit draft's privacy section asks for: a `KEYS guard:rl:*` scan no longer
 * yields a list of the accounts hitting the edge.
 *
 * 32 hex characters of SHA-256 is 128 bits against a keyspace of accounts, and
 * the key is an input to a bucket, not a secret: a collision would merge two
 * callers' allowances, not expose either.
 */
function bucket(policy: string, identity: string): string {
  const digest = createHash("sha256").update(identity, "utf8").digest("hex").slice(0, 32);

  return `${policy}:${digest}`;
}

/**
 * The headers, on every answered request.
 *
 * Two shapes, because clients in the field read two shapes and a gateway that
 * sends only one of them throttles nobody. There is no RFC for these fields yet;
 * the citation is the IETF HTTPAPI working group's Standards Track draft,
 * `draft-ietf-httpapi-ratelimit-headers-11` (Polli, Martinez Ruiz, Miller; 23 May
 * 2026), which builds on **RFC 9651** (Structured Field Values for HTTP) — not
 * RFC 9331, which is L4S/ECN and has nothing to do with rate limiting.
 *
 *   * §3 `RateLimit-Policy` — the quota policy, as a List of Items: the policy
 *     name as a String, `q` for the quota, `w` for the window in seconds.
 *       RateLimit-Policy: "guard-api";q=600;w=60
 *   * §4 `RateLimit` — the quota currently available under that policy: `r` for
 *     the available quota and, per §4.1.2, `t` for the *effective window*, "the
 *     number of seconds within which the client can use no more than the
 *     available quota". That is a countdown to the replenishment, not a copy of
 *     `w`: the draft's own examples show it moving (B.1.3 sends `r=60;t=58` two
 *     seconds into a hundred-a-minute policy; B.2.1 sends `r=99;t=50` under
 *     `q=100;w=60`). Sending the window here would tell a client its remaining
 *     quota lasts twice as long as it does.
 *       RateLimit: "guard-api";r=12;t=44
 *   * The un-prefixed `RateLimit-Limit`, `RateLimit-Remaining` and
 *     `RateLimit-Reset` trio, which the same draft dropped in -08 and which
 *     deployed clients and proxies still parse. `RateLimit-Reset` counts down in
 *     seconds, like `t`, so the two agree by construction.
 *   * This repository's own `X-RateLimit-*`, which is what guard sent before the
 *     draft existed: same numbers, and `X-RateLimit-Reset` as an absolute epoch
 *     instant, because a client that wants a wall-clock deadline should not have
 *     to reconstruct one from a delta.
 *
 * §6 lets a server return these regardless of status code, so they go on the 429
 * as well; §7 makes `Retry-After` take precedence when both are present, and
 * that is the order they are meant to be read in.
 */
function announce(
  c: Context,
  policy: { limit: number; windowMs: number; policy: string },
  verdict: { remaining: number; resetAt: number },
  at: number,
): void {
  const seconds = Math.max(0, Math.ceil(policy.windowMs / 1000));
  const effective = Math.max(0, Math.ceil((verdict.resetAt - at) / 1000));

  c.header("RateLimit-Policy", `"${policy.policy}";q=${policy.limit};w=${seconds}`);
  c.header("RateLimit", `"${policy.policy}";r=${verdict.remaining};t=${effective}`);
  c.header("RateLimit-Limit", String(policy.limit));
  c.header("RateLimit-Remaining", String(verdict.remaining));
  c.header("RateLimit-Reset", String(effective));
  c.header("X-RateLimit-Limit", String(policy.limit));
  c.header("X-RateLimit-Remaining", String(verdict.remaining));
  c.header("X-RateLimit-Reset", String(verdict.resetAt));
}

/**
 * A counter store that is not there.
 *
 * FAILS OPEN, and the cost is named rather than hidden: for as long as Redis is
 * unreachable, guard applies no limit at all. The alternative — failing closed —
 * hands an outage in the counter store to every caller as a 429, which is the
 * same class of mistake as restarting the process on a dependency blip, and much
 * harder to notice. A store that cannot answer has told us nothing about whether
 * the caller has spent anything, and guessing "no" is guessing in the direction
 * that keeps the edge serving.
 *
 * The headers are left off rather than guessed at, because a client told
 * `RateLimit-Limit: 600` and then never refused is worse than a client told
 * nothing. The store is a registered readiness probe, so `/readyz` says so.
 */
async function failedOpen(error: unknown, next: () => Promise<void>): Promise<Response | void> {
  // The message can name a host, a port and a bucket; the caller gets a request
  // with no rate-limit headers on it and no idea why.
  console.error("guard: the rate-limit store is unavailable; this request is not counted", error);

  await next();
}

/** The one 429 this repository writes. A fixed detail: nothing here varies. */
function throttled(): Problem {
  return { status: 429, code: "rate_limited", detail: "too many requests for this window" };
}
