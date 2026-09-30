// The contract every rate-limit backend owes guard.
//
// Split out from `rateLimitStore.ts` so `rateLimitRedis.ts` can depend on the
// types without pulling in the in-memory implementation, and so the trait is a
// file you can read on its own.

/**
 * What one request did to its bucket.
 *
 * `resetAt` and `retryAt` are two different instants, and conflating them is how
 * a client backs off for the wrong amount:
 *
 *   resetAt  when this caller is back to its *full* allowance.
 *   retryAt  when *this* request — the one that was refused — is admitted.
 *
 * On an admitted request `retryAt` is at or before `now`: it is already
 * admitted. On a refusal it is in the future, and it is what `Retry-After` says.
 */
export type Verdict = {
  allowed: boolean;
  /** Quota units left after this request. Never negative. */
  remaining: number;
  /** Epoch milliseconds at which the whole allowance is back. */
  resetAt: number;
  /** Epoch milliseconds at which this exact request would next be admitted. */
  retryAt: number;
};

export type RateLimitRequest = {
  /** Quota units per window. A whole number >= 1. */
  limit: number;
  /** Window length in milliseconds. A whole number >= 1. */
  windowMs: number;
  /** Epoch milliseconds, from the caller's clock so a test can move time. */
  now: number;
};

/**
 * One bucket, counted and read in a single step.
 *
 * The shape of this interface is the atomicity guarantee. There is deliberately
 * no `peek` to call before `hit`, so an implementation cannot read a count,
 * yield, and write a stale one back — and read-then-write is exactly what admits
 * N times the limit under a burst: every replica reads "4 used, limit 5" and all
 * five of them write "5 used". `rateLimit.test.ts` and `rateLimitParity.test.ts`
 * fire a burst at each implementation and assert the admitted count is exactly
 * the limit.
 *
 * Implementations throw when their storage is unreachable. Turning that into a
 * response is the middleware's decision and not the store's: a store that caught
 * its own failure and answered "no" would turn a dependency outage into a
 * platform-wide 429.
 */
export interface RateLimitStore {
  hit(key: string, request: RateLimitRequest): Promise<Verdict>;
}
