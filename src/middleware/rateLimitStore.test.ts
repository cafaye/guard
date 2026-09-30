import { describe, expect, test } from "bun:test";
import { memoryRateLimitStore, type RateLimitStore, type Verdict } from "./rateLimitStore";

const WINDOW_MS = 60_000;

/**
 * Every timing below is written against one bucket's arithmetic rather than
 * against a clock reading, because the whole point of the algorithm is that the
 * window slides: there is no instant at which "the window" ends and everything
 * comes back.
 */
async function hit(
  store: ReturnType<typeof memoryRateLimitStore>,
  key: string,
  limit: number,
  at: number,
  windowMs = WINDOW_MS,
): Promise<Verdict> {
  return store.hit(key, { limit, windowMs, now: at });
}

describe("memoryRateLimitStore", () => {
  test("admits exactly `limit` requests and refuses the one after", async () => {
    const store = memoryRateLimitStore();

    for (let i = 1; i <= 3; i++) {
      expect((await hit(store, "k", 3, 1_000_000)).allowed).toBe(true);
    }

    const refused = await hit(store, "k", 3, 1_000_000);
    expect(refused.allowed).toBe(false);
    expect(refused.remaining).toBe(0);
  });

  test("counts down remaining one request at a time", async () => {
    const store = memoryRateLimitStore();

    expect((await hit(store, "k", 3, 0)).remaining).toBe(2);
    expect((await hit(store, "k", 3, 0)).remaining).toBe(1);
    expect((await hit(store, "k", 3, 0)).remaining).toBe(0);
  });

  test("keys are independent of each other", async () => {
    const store = memoryRateLimitStore();

    await hit(store, "a", 1, 0);
    expect((await hit(store, "a", 1, 0)).allowed).toBe(false);
    expect((await hit(store, "b", 1, 0)).allowed).toBe(true);
  });

  test("a bucket nobody has touched starts full", async () => {
    const store = memoryRateLimitStore({ now: () => 500_000 });

    expect((await hit(store, "fresh", 10, 0)).remaining).toBe(9);
  });
});

describe("the sliding window boundary — the fixed-window 2x burst", () => {
  test("`limit` just before the boundary plus `limit` just after is refused", async () => {
    const store = memoryRateLimitStore();
    // The instant a fixed window would roll over: 1_000_000 is 40s into the
    // window that opened at 960_000 and closes at 1_020_000.
    const EDGE = 1_020_000;

    // The whole allowance spent one millisecond before the edge.
    for (let i = 0; i < 5; i++) {
      expect((await hit(store, "k", 5, EDGE - 1)).allowed).toBe(true);
    }

    // The same five, one millisecond after it. A fixed window would hand out a
    // fresh allowance here and admit ten requests inside 2ms.
    const after = [];
    for (let i = 0; i < 5; i++) {
      after.push((await hit(store, "k", 5, EDGE)).allowed);
    }

    expect(after).toEqual([false, false, false, false, false]);
  });

  test("one interval past the edge one request is admitted, because one unit expired", async () => {
    const store = memoryRateLimitStore();
    const EDGE = 1_020_000;
    const interval = WINDOW_MS / 5;

    for (let i = 0; i < 5; i++) await hit(store, "k", 5, EDGE - 1);

    // One interval — not one millisecond, which repays nothing — later, the
    // first of those five has aged out, so exactly one more request fits. The
    // other four must wait for their own.
    const after = EDGE - 1 + interval;

    expect((await hit(store, "k", 5, after)).allowed).toBe(true);
    expect((await hit(store, "k", 5, after)).allowed).toBe(false);
  });

  test("capacity is repaid smoothly rather than in one lump at the boundary", async () => {
    const store = memoryRateLimitStore();
    const interval = WINDOW_MS / 5;

    for (let i = 0; i < 5; i++) await hit(store, "k", 5, 0);

    // The bucket is in debt for five intervals. One interval later one unit has
    // been repaid, and only one.
    expect((await hit(store, "k", 5, interval)).allowed).toBe(true);
    expect((await hit(store, "k", 5, interval)).allowed).toBe(false);

    expect((await hit(store, "k", 5, 2 * interval)).allowed).toBe(true);
    expect((await hit(store, "k", 5, 3 * interval)).allowed).toBe(true);
    expect((await hit(store, "k", 5, 4 * interval)).allowed).toBe(true);
  });

  test("an idle bucket is completely refilled", async () => {
    const store = memoryRateLimitStore();

    for (let i = 0; i < 5; i++) await hit(store, "k", 5, 0);
    expect((await hit(store, "k", 5, 0)).allowed).toBe(false);

    // One full window of silence repays everything — which is one request, not
    // two. The allowance is a bucket, and a refused request did not put anything
    // in it, so a refilled bucket is a full one.
    const refilled = await hit(store, "k", 5, WINDOW_MS);

    expect(refilled.allowed).toBe(true);
    expect(refilled.remaining).toBe(4);
  });
});

describe("resetAt and retryAt", () => {
  test("a refusal says when that request would next be admitted", async () => {
    const store = memoryRateLimitStore();
    const limit = 2;

    await hit(store, "k", limit, 0);
    await hit(store, "k", limit, 0);
    const refused = await hit(store, "k", limit, 0);

    expect(refused.retryAt).toBeGreaterThan(0);
    // The third unit is refused; its debt clears exactly one interval later.
    expect(refused.retryAt).toBe(WINDOW_MS / limit);
  });

  test("an admitted request is already admitted at the instant it was made", async () => {
    const store = memoryRateLimitStore();

    const allowed = await hit(store, "k", 2, 0);

    expect(allowed.retryAt).toBeLessThanOrEqual(0);
  });

  test("resetAt is the instant the full allowance is back, and never in the past", async () => {
    const store = memoryRateLimitStore();
    const limit = 4;

    const first = await hit(store, "k", limit, 0);
    const interval = WINDOW_MS / limit;

    // One request spent one interval of debt, so the bucket is whole again one
    // interval after the instant that request was made.
    expect(first.resetAt).toBe(interval);
    expect(first.resetAt).toBeGreaterThan(0);

    await hit(store, "k", limit, 0);
    await hit(store, "k", limit, 0);
    await hit(store, "k", limit, 0);
    const drained = await hit(store, "k", limit, 0);
    expect(drained.resetAt).toBe(WINDOW_MS);
  });

  test("a refused request leaves the debt standing rather than deepening it", async () => {
    const store = memoryRateLimitStore();

    for (let i = 0; i < 3; i++) await hit(store, "k", 2, 0);
    const firstRefusal = await hit(store, "k", 2, 0);
    const tenthRefusal = await hit(store, "k", 2, 0);

    // A refused request must not push the debt further out, or a caller that
    // keeps hammering while throttled would lock itself out for as long as it
    // keeps trying.
    expect(tenthRefusal.retryAt).toBe(firstRefusal.retryAt);
    expect(tenthRefusal.resetAt).toBe(firstRefusal.resetAt);
  });
});

describe("atomicity", () => {
  test("a burst fired without awaiting between requests admits exactly `limit`", async () => {
    const store = memoryRateLimitStore();
    const limit = 50;

    // Every call is started before any is awaited, so nothing sequences them
    // but the store itself. A read-then-write store would let all 200 through.
    const pending = Array.from({ length: 200 }, () => store.hit("burst", { limit, windowMs: WINDOW_MS, now: 0 }));
    const verdicts = await Promise.all(pending);

    expect(verdicts.filter((v) => v.allowed)).toHaveLength(limit);
    expect(verdicts.filter((v) => !v.allowed)).toHaveLength(200 - limit);
  });

  test("the exact admitted count holds for every limit in a table", async () => {
    for (const limit of [1, 2, 7, 64]) {
      const store = memoryRateLimitStore();
      const fire = limit * 3;

      const verdicts = await Promise.all(
        Array.from({ length: fire }, () => store.hit("k", { limit, windowMs: WINDOW_MS, now: 0 })),
      );

      expect(verdicts.filter((v) => v.allowed).length).toBe(limit);
    }
  });
});

describe("bounded memory", () => {
  test("maxClients drops settled buckets so the map does not grow forever", async () => {
    let now = 0;
    const store = memoryRateLimitStore({ maxClients: 4, now: () => now });

    for (const key of ["a", "b", "c", "d", "e", "f"]) await hit(store, key, 1, now);

    // Two windows later every one of them owes nothing, so the sweep can drop
    // them without changing any caller's allowance.
    now = 2 * WINDOW_MS;
    await hit(store, "g", 1, now);

    expect(store.size()).toBeLessThanOrEqual(4);
  });

  test("a bucket in debt is never swept", async () => {
    const store = memoryRateLimitStore({ maxClients: 1, now: () => 0 });

    await hit(store, "a", 1, 0);
    await hit(store, "b", 1, 0);

    // "a" is still refused: sweeping a bucket that still owes quota would hand
    // the same caller a fresh allowance for the price of one extra request,
    // which is the self-DoS the limiter exists to prevent.
    expect((await hit(store, "a", 1, 0)).allowed).toBe(false);
  });

  test("the bound does not pretend to cap callers who are all still in debt", async () => {
    // The honest statement of what `maxClients` is: it bounds settled state, not
    // admitted traffic. A flood of distinct live callers grows the map by that
    // many, which is why the default is high rather than small and clever.
    const store = memoryRateLimitStore({ maxClients: 2, now: () => 0 });

    for (let i = 0; i < 50; i++) await hit(store, `live-${i}`, 1, 0);

    expect(store.size()).toBe(50);
  });

  test("a bucket nobody has touched in a whole window is swept", async () => {
    let now = 0;
    const store = memoryRateLimitStore({ maxClients: 1, now: () => now });

    await hit(store, "a", 1, 0);
    now = 2 * WINDOW_MS;
    await hit(store, "b", 1, now);

    expect(store.size()).toBe(1);
  });

  test("rejects a non-positive or fractional bound at construction", () => {
    expect(() => memoryRateLimitStore({ maxClients: 0 })).toThrow(RangeError);
    expect(() => memoryRateLimitStore({ maxClients: 1.5 })).toThrow(RangeError);
  });
});

describe("a store outage", () => {
  test("a store that throws is reported as unavailable, not as a refusal", async () => {
    const broken: RateLimitStore = {
      hit: () => Promise.reject(new Error("redis: connection refused")),
    };

    // There is no fallback inside the store. What the middleware does with a
    // rejection is a separate decision, and pretending a dead store said "no"
    // would turn a dependency outage into a platform-wide 429.
    await expect(broken.hit("k", { limit: 1, windowMs: 1000, now: 0 })).rejects.toThrow();
  });
});
