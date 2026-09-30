// Where the rate-limit counters live.
//
// The limiter itself (`./rateLimit`) decides *which* bucket a request belongs
// to and what to say about it; this file decides how that bucket is counted,
// and there are two answers because there are two deployments:
//
//   memory  one process, lost on restart. Correct for a single instance.
//   redis   shared by every replica and across restarts (`./rateLimitRedis`).
//
// Both sit behind `RateLimitStore`, and `rateLimitParity.test.ts` runs one
// behaviour table through both, so the abstraction is proven rather than
// asserted. `../index.ts` picks between them from `REDIS_URL`.
import { assertPositiveInteger } from "./assert";
import type { RateLimitStore, RateLimitRequest, Verdict } from "./rateLimitTypes";

export type { RateLimitStore, RateLimitRequest, Verdict } from "./rateLimitTypes";

export type MemoryRateLimitStoreOptions = {
  /**
   * Buckets held before *settled* ones are swept. This bounds settled state,
   * not admitted traffic: a bucket that still owes quota is never swept, so the
   * map can hold `maxClients` plus every caller active in the current window.
   * Evicting a bucket in debt would be cheaper and would be wrong — forgetting
   * one hands that caller a fresh allowance for the price of one extra request,
   * which is the self-DoS a rate limiter exists to prevent.
   */
  maxClients?: number;
};

/**
 * There is no clock option here, and that is deliberate.
 *
 * `RateLimitRequest.now` is the only clock this store reads. A second one at
 * construction would be a second answer to "what time is it" in the same
 * process, and the two could disagree — a bucket aged by the constructor's clock
 * and a request stamped by the caller's is a limiter whose arithmetic depends on
 * which of two clocks reached it first.
 */

export type MemoryRateLimitStore = RateLimitStore & {
  /** Buckets held right now. v0 introspection, deliberately off the trait. */
  size(): number;
};

const DEFAULT_MAX_CLIENTS = 100_000;

/**
 * In-memory counting, per process.
 *
 * SINGLE-INSTANCE ONLY, and said so here, in the README and in the compose file
 * rather than in a line nobody reads: a caller gets `limit` per window from
 * *each* replica, so N replicas is an N× limit, and every bucket is lost on
 * restart. `rateLimitParity.test.ts` pins the difference by showing two of
 * these disagreeing where two Redis-backed ones share one bucket.
 */
export function memoryRateLimitStore(options: MemoryRateLimitStoreOptions = {}): MemoryRateLimitStore {
  const { maxClients = DEFAULT_MAX_CLIENTS } = options;
  assertPositiveInteger(maxClients, "maxClients");

  /**
   * bucket key -> the instant its debt clears (GCRA's "theoretical arrival
   * time", `tat`).
   */
  const buckets = new Map<string, number>();

  return {
    async hit(key, request) {
      // Everything between the read and the write in `count` is synchronous,
      // and that is the whole atomicity argument: a JavaScript turn cannot be
      // interleaved, so no caller ever observes `buckets` mid-update. Firing
      // 200 concurrent `hit`s at a limit of 50 still admits exactly 50. The
      // Redis backend gets the same property from one Lua script, and
      // `rateLimitParity.test.ts` runs that burst against both.
      if (buckets.size >= maxClients) sweepSettled(buckets, request.now);
      return count(buckets, key, request);
    },

    size() {
      return buckets.size;
    },
  };
}

/**
 * GCRA — a smooth sliding window, in one number per bucket.
 *
 * A caller is thought of as owing `tat - now` of time. Each request adds
 * `windowMs / limit` to the debt; time passing repays it continuously rather
 * than in a lump at an edge. A request is admitted when the debt it would leave
 * is no more than one whole window, which is the sliding-window bound: at most
 * `limit` requests in any window of `windowMs`.
 *
 * A fixed window cannot say that. It hands out `limit` per aligned bucket of
 * time, so `limit` requests one millisecond before the edge plus `limit` one
 * millisecond after it is 2× the allowance inside two milliseconds.
 * `rateLimitStore.test.ts` writes that case out; it is the reason this file
 * exists instead of the code it replaced.
 *
 * The alternative to GCRA is a sorted set of request timestamps, which is also
 * exact and costs one stored entry per request per window. GCRA costs one number
 * per caller, and both take one round trip — which is the property that matters
 * at the edge.
 */
export function count(state: Map<string, number>, key: string, { limit, windowMs, now }: RateLimitRequest): Verdict {
  const debt = state.get(key) ?? 0;
  const interval = windowMs / limit;

  // `now < debt` means the caller is still in debt from before: the new request
  // queues behind it rather than being forgiven because the clock moved.
  const next = Math.max(now, debt) + interval;
  const delay = next - now;

  // Strictly greater, so a caller sitting exactly on the threshold is admitted:
  // that is what lets a burst of exactly `limit` land.
  if (delay > windowMs) {
    // Nothing is written. A refused request must not deepen the debt, or a
    // caller that keeps hammering while throttled locks itself out for as long
    // as it keeps trying.
    return { allowed: false, remaining: 0, resetAt: debt, retryAt: next - windowMs };
  }

  state.set(key, next);

  return {
    allowed: true,
    remaining: Math.max(0, limit - Math.ceil((next - now) / interval)),
    // The whole allowance is back once the debt has been repaid in full, which
    // is at `next`. Before this request it stood at `debt`, so one request
    // costs exactly one interval of that.
    resetAt: next,
    // Already admitted at `now`, so this is at or before it. Only the refusal
    // branch above produces a future value, and that is the `Retry-After`.
    retryAt: next - interval - windowMs,
  };
}

/**
 * Drops buckets whose debt has already been repaid.
 *
 * A bucket at `tat <= now` owes nothing, so forgetting it hands the caller
 * exactly the allowance they had already earned — no more and no less, which is
 * why this is safe. A bucket still in debt is never swept.
 */
export function sweepSettled(buckets: Map<string, number>, at: number): void {
  for (const [key, tat] of buckets) if (tat <= at) buckets.delete(key);
}
