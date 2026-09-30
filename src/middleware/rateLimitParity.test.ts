// One behaviour table, two implementations.
//
// This is the file that proves `RateLimitStore` is a real abstraction and not
// decoration: every case below runs twice, once against the in-memory store and
// once against the Redis store, and the two verdicts must be byte-identical. A
// limiter where only one backend has been exercised is a limiter whose
// distributed path is untested until it is in production.
//
// The Redis store is driven by the fake in `rateLimitRedis.test.ts`; nothing
// here opens a socket, and no test in this repository contacts a Redis server.
import { describe, expect, test } from "bun:test";
import { memoryRateLimitStore, type RateLimitStore } from "./rateLimitStore";
import { redisRateLimitStore, type RedisCommands } from "./rateLimitRedis";
import { GCRA_LUA } from "./rateLimitRedis";

const WINDOW_MS = 60_000;

/** The fake's script body, transcribed from GCRA_LUA. See that file for why. */
function fakeRedis(): RedisCommands {
  const keys = new Map<string, number>();

  return {
    async eval(script, keysIn, args) {
      if (script !== GCRA_LUA) throw new Error("unexpected script");
      const key = keysIn[0] ?? "";
      const limit = Number(args[0]);
      const windowMs = Number(args[1]);
      const now = Number(args[2]);

      const tat = keys.get(key) ?? 0;
      const interval = windowMs / limit;
      const next = Math.max(now, tat) + interval;
      const delay = next - now;

      if (delay > windowMs) return [0, tat, next - windowMs, 0];

      keys.set(key, next);
      return [1, next, next - interval - windowMs, Math.max(0, limit - Math.ceil((next - now) / interval))];
    },
    async ping() {
      return true;
    },
  };
}

const IMPLEMENTATIONS: Array<{ name: string; build: () => RateLimitStore }> = [
  { name: "memory", build: () => memoryRateLimitStore() },
  { name: "redis", build: () => redisRateLimitStore({ commands: fakeRedis() }) },
];

/** One row of the table: a script of requests, and what each answer is. */
type Row = {
  what: string;
  limit: number;
  windowMs: number;
  /** Times, in milliseconds, to hit at, in order. */
  at: number[];
  /** Expected allowed/remaining pairs, in order. */
  expected: Array<[allowed: boolean, remaining: number]>;
};

const TABLE: Row[] = [
  {
    what: "the allowance is spent one request at a time",
    limit: 3,
    windowMs: WINDOW_MS,
    at: [0, 0, 0, 0, 0],
    expected: [
      [true, 2],
      [true, 1],
      [true, 0],
      [false, 0],
      [false, 0],
    ],
  },
  {
    what: "a limit of one refuses the second request in the same instant",
    limit: 1,
    windowMs: WINDOW_MS,
    at: [0, 0, 1, WINDOW_MS],
    expected: [
      [true, 0],
      [false, 0],
      [false, 0],
      [true, 0],
    ],
  },
  {
    what: "the sliding-window boundary: 5 before the edge, 5 after it",
    limit: 5,
    windowMs: WINDOW_MS,
    at: [
      1_019_999, 1_019_999, 1_019_999, 1_019_999, 1_019_999,
      1_020_000, 1_020_000, 1_020_000, 1_020_000, 1_020_000,
    ],
    expected: [
      [true, 4],
      [true, 3],
      [true, 2],
      [true, 1],
      [true, 0],
      [false, 0],
      [false, 0],
      [false, 0],
      [false, 0],
      [false, 0],
    ],
  },
  {
    what: "capacity is repaid one interval at a time after the boundary",
    limit: 5,
    windowMs: WINDOW_MS,
    // Debt after the five refused requests above runs to five intervals; each
    // interval repays exactly one, so the allowance walks back rather than
    // arriving in a lump.
    at: [1_020_000, 1_032_000, 1_044_000, 1_056_000, 1_068_000, 1_080_000, 1_092_000, 1_104_000],
    expected: [
      [false, 0],
      [true, 0],
      [true, 0],
      [true, 1],
      [true, 2],
      [true, 3],
      [false, 0],
      [true, 2],
    ],
  },
  {
    what: "crossing the aligned-window edge buys no second allowance",
    limit: 2,
    windowMs: 10_000,
    // 10_000 is where a wall-clock-aligned fixed window would have rolled.
    at: [9_999, 10_000, 10_001],
    expected: [
      [true, 1],
      [true, 1],
      [false, 0],
    ],
  },
  {
    what: "a window of silence repays everything",
    limit: 4,
    windowMs: 1_000,
    at: [0, 0, 0, 0, 0, 1_000],
    expected: [
      [true, 3],
      [true, 2],
      [true, 1],
      [true, 0],
      [false, 0],
      [true, 3],
    ],
  },
  {
    what: "a caller that paces itself evenly never trips the limiter",
    limit: 4,
    windowMs: 10_000,
    at: [0, 2_500, 5_000, 7_500, 10_000, 12_500, 15_000],
    expected: [
      [true, 3],
      [true, 2],
      [true, 1],
      [true, 0],
      [true, 3],
      [true, 2],
      [true, 1],
    ],
  },
  {
    what: "a window shorter than the limit still admits exactly the limit",
    limit: 100,
    windowMs: 100,
    at: Array.from({ length: 150 }, () => 0),
    expected: Array.from({ length: 150 }, (_, i): [boolean, number] =>
      i < 100 ? [true, 99 - i] : [false, 0],
    ),
  },
];

for (const { name, build } of IMPLEMENTATIONS) {
  describe(`parity: ${name}`, () => {
    for (const [rowIndex, row] of TABLE.entries()) {
      test(row.what, async () => {
        const store = build();

        const seen: Array<[boolean, number]> = [];
        for (let i = 0; i < row.at.length; i++) {
          const at = row.at[i];
          const verdict = await store.hit(`row-${rowIndex}`, {
            limit: row.limit,
            windowMs: row.windowMs,
            now: at ?? 0,
          });
          seen.push([verdict.allowed, verdict.remaining]);
        }

        expect(seen).toEqual(row.expected);
      });
    }

    test("resetAt and retryAt agree with the memory store's arithmetic", async () => {
      const store = build();
      const limit = 4;
      const interval = WINDOW_MS / limit;

      const first = await store.hit("timing", { limit, windowMs: WINDOW_MS, now: 0 });
      expect(first.resetAt).toBe(interval);
      expect(first.retryAt).toBeLessThanOrEqual(0);

      for (let i = 1; i < limit; i++) await store.hit("timing", { limit, windowMs: WINDOW_MS, now: 0 });
      const refused = await store.hit("timing", { limit, windowMs: WINDOW_MS, now: 0 });

      expect(refused.allowed).toBe(false);
      expect(refused.retryAt).toBe(interval);
      expect(refused.resetAt).toBe(WINDOW_MS);
    });

    test("keys do not share a bucket", async () => {
      const store = build();
      const limit = 1;

      expect((await store.hit("a", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
      expect((await store.hit("a", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(false);
      expect((await store.hit("b", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
    });

    test("a burst fired at once admits exactly `limit`", async () => {
      const store = build();
      const limit = 128;

      const verdicts = await Promise.all(
        Array.from({ length: 512 }, () => store.hit("burst", { limit, windowMs: WINDOW_MS, now: 0 })),
      );

      expect(verdicts.filter((v) => v.allowed).length).toBe(limit);
      expect(verdicts.filter((v) => !v.allowed).length).toBe(512 - limit);
    });
  });
}

test("the two implementations answer the whole table identically", async () => {
  const transcript = async (build: () => RateLimitStore): Promise<string> => {
    const lines: string[] = [];
    for (const [rowIndex, row] of TABLE.entries()) {
      const store = build();
      for (let i = 0; i < row.at.length; i++) {
        const verdict = await store.hit(`row-${rowIndex}`, {
          limit: row.limit,
          windowMs: row.windowMs,
          now: row.at[i] ?? 0,
        });
        lines.push(`row-${rowIndex}#${i} ${verdict.allowed} ${verdict.remaining} ${verdict.resetAt} ${verdict.retryAt}`);
      }
    }
    return lines.join("\n");
  };

  expect(await transcript(IMPLEMENTATIONS[1]!.build)).toBe(await transcript(IMPLEMENTATIONS[0]!.build));
});

test("two stores over the same fake share one bucket, the way two replicas do", async () => {
  // This is the property the Redis backend exists for, and it is only true
  // because the counter lives outside the process. The memory store cannot do
  // it: two of them are two buckets, which is exactly the v0 hole.
  const commands = fakeRedis();
  const replicaA = redisRateLimitStore({ commands });
  const replicaB = redisRateLimitStore({ commands });
  const limit = 2;

  expect((await replicaA.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
  expect((await replicaB.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
  expect((await replicaA.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(false);

  const localA = memoryRateLimitStore();
  const localB = memoryRateLimitStore();
  expect((await localA.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
  expect((await localA.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
  expect((await localA.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(false);
  expect((await localB.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
  expect((await localB.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
  expect((await localB.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(false);
  // Six requests, one allowance of two, two processes: four were admitted. The
  // Redis pair above admitted exactly two. That gap *is* the v0 hole.
});
