// The Redis backend, executed by a real redis-server.
//
// Every other test in this repository drives the Redis path without a server:
// `rateLimitRedis.test.ts` transcribes GCRA_LUA into JavaScript and runs the
// transcript, and `rateLimitParity.test.ts` requires the two stores to agree over
// one behaviour table. That proves the client — key names, argument marshalling,
// reply decoding — and it leaves the *script* covered by review. A Lua body no
// test has run is a body that is correct by assertion rather than by evidence,
// and it is the body that decides whether a deployment with `REDIS_URL` set
// limits at all.
//
// This file closes that gap. It is the tier PLAN.md §1 is about: the hard part
// is the script and the socket, a CI run is the only place either can be forced,
// and a run that quietly skips them has verified nothing.
//
// Gated on `GUARD_REDIS_URL`:
//
//   bun test src/middleware/rateLimitRedisLive.test.ts            # skips
//   GUARD_REDIS_URL=redis://127.0.0.1:6379 bun test ...           # runs
//
// `GUARD_REDIS_REQUIRED=true` turns "no URL" from a skip into a failure, and it
// is what the CI job sets. A skip nobody is forced to notice is the exact shape
// this file exists to prevent, so the gate that says *this tier must run* is
// asserted by the tier itself rather than left to a reader of the log.
//
// Everything here goes through `connectRedis`, the same transport production
// uses, including the commands the store does not expose: `RedisCommands` is
// deliberately two methods wide, and widening it for a test would trade a
// reviewed interface for a second, divergent way of talking to Redis.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  connectRedis,
  GCRA_LUA,
  lazyRedis,
  redisRateLimitStore,
  type RedisCommands,
} from "./rateLimitRedis";
import { memoryRateLimitStore } from "./rateLimitStore";
import type { RateLimitStore, Verdict } from "./rateLimitTypes";

const REDIS_URL = process.env.GUARD_REDIS_URL?.trim();
const REQUIRED = process.env.GUARD_REDIS_REQUIRED === "true";

if (REQUIRED && REDIS_URL === undefined) {
  // Thrown at module load, before a test is registered, so a run that was supposed
  // to execute the script and could not says so in its first line of output
  // rather than in a summary of zero passes.
  throw new Error(
    "GUARD_REDIS_REQUIRED=true and GUARD_REDIS_URL is unset. The live Redis tier cannot run, " +
      "and a run that cannot run it proves nothing about GCRA_LUA. Point GUARD_REDIS_URL at a " +
      "redis-server, or unset GUARD_REDIS_REQUIRED to skip this tier on purpose.",
  );
}

/**
 * One namespace per run, so two runs against one server — a developer's leftover
 * daemon and a CI container, or two worktrees — cannot read each other's buckets
 * and turn stale state into a red suite. The store's own charset check
 * (`[A-Za-z0-9_.:-]`) is exercised by the value put in front of it.
 */
const RUN = `live-${crypto.randomUUID()}`;

const WINDOW_MS = 60_000;

/** Every key this run wrote, so `afterAll` can take them with it. */
const written = new Set<string>();

let a: RedisCommands & { close(): void };
let b: RedisCommands & { close(): void };

/**
 * The hooks are no-ops when the tier is skipped. `beforeAll` runs whether or not
 * any test in the file does, so an unconditional `connectRedis` here would turn
 * "deliberately skipped" into "two failures" — and a skip that reports as red is a
 * skip nobody leaves in place on purpose.
 */
beforeAll(async () => {
  if (REDIS_URL === undefined) return;
  a = await connectRedis({ url: REDIS_URL });
  b = await connectRedis({ url: REDIS_URL });
});

afterAll(async () => {
  if (a === undefined) return;
  // Every bucket this run wrote carries a PX equal to its window, so Redis would
  // reclaim it on its own. Deleting explicitly leaves a developer's daemon as it
  // was found, and it doubles as a check that the namespace is ours alone.
  for (const key of written) await a.eval("return redis.call('DEL', KEYS[1])", [key], []);
  a.close();
  b.close();
});

/**
 * A store over `commands`, in a bucket namespace of its own.
 *
 * The namespace is per call rather than per run on purpose: two tests in one file
 * that share a bucket share its debt, and a test that starts with a bucket already
 * spent fails for a reason that has nothing to do with what it is checking.
 */
function live(commands: RedisCommands, name: string): RateLimitStore & { keyFor(bucket: string): string } {
  const store = redisRateLimitStore({ commands, prefix: `${RUN}.${name}` });
  const hit = store.hit.bind(store);

  return {
    keyFor: store.keyFor,
    async hit(bucket, request) {
      written.add(store.keyFor(bucket));
      return hit(bucket, request);
    },
  };
}

/** One `redis.call` for a single key, over the production transport. */
function call(commands: RedisCommands, script: string, key: string): Promise<unknown> {
  return commands.eval(script, [key], []);
}

/**
 * Two verdicts compared the way redis-server actually produces them.
 *
 * Redis returns a Lua number as an **integer, truncated toward zero** — `2.5`
 * comes back as `2`, `-0.5` as `0`. That is a property of the server's Lua-to-RESP
 * conversion, not of `GCRA_LUA`, and it is why the two implementations agree on
 * what they *decide* and not on the last decimal of a timestamp.
 *
 * So this is an exact comparison, not a tolerance: the decision fields are
 * integral on both sides and must be identical, and the two timestamps must equal
 * the memory store's truncated toward zero. A blanket `toBeCloseTo` would let a
 * regression of any size through under the name of a rounding difference; this
 * states the mechanism, so a server that changed its conversion fails the test
 * instead of quietly widening what passes.
 */
function expectSameVerdict(received: Verdict, expected: Verdict, label: string): void {
  expect(`${label} allowed ${received.allowed}`).toBe(`${label} allowed ${expected.allowed}`);
  expect(`${label} remaining ${received.remaining}`).toBe(`${label} remaining ${expected.remaining}`);
  expect(`${label} resetAt ${received.resetAt}`).toBe(`${label} resetAt ${Math.trunc(expected.resetAt)}`);
  expect(`${label} retryAt ${received.retryAt}`).toBe(`${label} retryAt ${Math.trunc(expected.retryAt)}`);
}

describe.skipIf(REDIS_URL === undefined)("live redis: the transport", () => {
  test("a real server answers PING with PONG", async () => {
    expect(await a.ping()).toBe(true);
    expect(await b.ping()).toBe(true);
  });

  test("the reply decoder reads the three shapes GCRA_LUA can produce", async () => {
    // A bulk string, an integer and an array, all from the server, decoded by the
    // `parseReply` the store relies on. `verdictOf` throws on any other shape
    // rather than inferring `allowed` from it, so what the server sends is pinned
    // here before the store is trusted to read it.
    const key = `${RUN}:shapes`;
    expect(await call(a, "return redis.call('SET', KEYS[1], 'hello')", key)).toBe("OK");
    expect(await call(a, "return redis.call('GET', KEYS[1])", key)).toBe("hello");
    expect(await call(a, "return 42", key)).toBe(42);
    expect(await call(a, "return {1, 2, 3}", key)).toEqual([1, 2, 3]);

    // The error reply is the fourth shape, and it is the one that matters most: a
    // `-ERR` from EVAL means the script did not run, and reading it as "no quota
    // used" would be a limiter that opens exactly when its dependency is broken.
    await expect(call(a, "return redis.call('INCR', KEYS[1])", key)).rejects.toThrow();

    written.add(key);
  });

  test("the GCRA script's own reply is the four integers the store expects", async () => {
    const key = `${RUN}:shape4`;
    const reply = await a.eval(GCRA_LUA, [key], ["3", String(WINDOW_MS), "0"]);

    expect(Array.isArray(reply)).toBe(true);
    expect(reply).toHaveLength(4);
    for (const part of reply as unknown[]) {
      expect(typeof part).toBe("number");
      expect(Number.isInteger(part as number)).toBe(true);
    }
    written.add(key);
  });

  test("an error reply fails one command, not the connection", async () => {
    // Regression, found by this tier: a single `-ERR` used to wedge the socket
    // permanently. `drain` caught every `parseReply` throw, consumed no bytes and
    // resolved no waiter, so the same `-ERR` was re-parsed on every later chunk and
    // every later command on that connection timed out — for the life of the
    // process. `lazyRedis` caches a connection, so a gateway hit once would fail
    // open on every request until it restarted, and `/readyz` would say
    // `redis: unavailable` with nothing in the log saying why.
    //
    // An error reply is part of RESP, not a desync: Redis sends one deliberately and
    // the stream stays in sync. So it has to reject the command that asked for it
    // and leave the connection usable, which is what this asserts.
    const key = `${RUN}:err`;
    expect(await call(a, "return redis.call('SET', KEYS[1], 'not-a-number')", key)).toBe("OK");

    await expect(call(a, "return redis.call('INCR', KEYS[1])", key)).rejects.toThrow(/not an integer/);

    // The connection still answers, and still answers in order.
    expect(await a.ping()).toBe(true);
    expect(await call(a, "return redis.call('GET', KEYS[1])", key)).toBe("not-a-number");
    expect(await call(a, "return 1", key)).toBe(1);

    written.add(key);
  });

  test("an error reply leaves a store that keeps counting", async () => {
    // The same wedge seen through the store rather than the transport, because
    // "the limiter stopped counting and nothing said so" is the failure that
    // matters. A store whose script comes back `-ERR` must throw for that one
    // request — the middleware then fails open, visibly — and the next one must be
    // counted normally.
    const store = live(a, "errored");
    const key = store.keyFor("acct:1");
    const limit = 3;
    const request = { limit, windowMs: WINDOW_MS, now: 0 };

    for (let i = 0; i < limit; i++) expect((await store.hit("acct:1", request)).allowed).toBe(true);
    expect((await store.hit("acct:1", request)).allowed).toBe(false);

    // Break the script the way a key collision with another subsystem would: a list
    // where the script expects a string, so its own `GET` answers `-WRONGTYPE` and
    // EVAL hands that back. This is a real failure mode, not a mock: it needs the
    // server to refuse, which is the only way to produce the reply in the first
    // place. The key the counting above left behind is the one that gets clobbered.
    expect(await call(a, "return redis.call('DEL', KEYS[1])", key)).toBe(1);
    expect(await call(a, "return redis.call('LPUSH', KEYS[1], 'not-a-string')", key)).toBe(1);

    await expect(store.hit("acct:1", request)).rejects.toThrow(/WRONGTYPE/);
    await expect(store.hit("acct:1", request)).rejects.toThrow(/WRONGTYPE/);

    // The connection is unharmed by the two that threw, and the store counts again
    // the moment the key is the type the script expects.
    expect(await a.ping()).toBe(true);
    expect(await call(a, "return redis.call('DEL', KEYS[1])", key)).toBe(1);
    expect((await store.hit("acct:1", { limit, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
  });

  test("an unreachable server throws rather than resolving, which is what makes the limiter fail open", async () => {
    // Failing open costs the whole limit for as long as the store is down, and that
    // trade is only honest if the store really does throw when Redis is gone. A
    // connection that resolved on a refused port would turn an outage into a
    // limiter answering "allowed" with no error anywhere. The port is opened and
    // released by this test, so the check cannot collide with a developer's Redis.
    const listener = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
    const port = listener.port;
    listener.stop(true);

    // `connectRedis` is eager, so it refuses to hand back a client at all.
    await expect(connectRedis({ url: `redis://127.0.0.1:${port}`, timeoutMs: 500 })).rejects.toThrow();

    // `lazyRedis` is what production builds, and its contract is the interesting
    // one: a down Redis is not a refusal to boot, it is an unavailable dependency
    // that the first command reports and the next one retries.
    const lazy = lazyRedis({ url: `redis://127.0.0.1:${port}`, timeoutMs: 500 });
    await expect(lazy.ping()).rejects.toThrow();
    await expect(lazy.ping()).rejects.toThrow();
    lazy.close();
  });
});

describe.skipIf(REDIS_URL === undefined)("live redis: GCRA_LUA, executed by redis-server", () => {
  test("the script and the in-memory store answer the same request identically", async () => {
    // The oracle is `count()` in `rateLimitStore.ts`, not the transcription in
    // `rateLimitRedis.test.ts`. That is deliberate: if the transcription and the
    // script were both wrong the same way, the transcription-based parity suite
    // would stay green, and only a comparison against the implementation the
    // memory store is built from can tell.
    const limit = 5;
    const windowMs = 10_000;
    const requests = Array.from({ length: 24 }, (_, i) => ({ limit, windowMs, now: i * 700 }));

    const memory = memoryRateLimitStore();
    const server = live(a, "identical");
    let refusals = 0;

    for (const [i, request] of requests.entries()) {
      const expected = await memory.hit("acct:1", request);
      if (!expected.allowed) refusals++;
      expectSameVerdict(await server.hit("acct:1", request), expected, `#${i}`);
    }

    // The table has to have refused something, or it has proved that nothing
    // happens rather than that the two agree.
    expect(refusals).toBeGreaterThan(0);
  });

  test("the script and the in-memory store agree across randomised limits, windows and clocks", async () => {
    // A fixed seed, generated not slept: no wall clock, no `Date.now`, nothing to
    // flake. A 32-bit LCG is enough — this needs a spread of shapes, not
    // statistical quality, and a seeded sequence is reproducible in CI.
    let state = 0x5eed_1234;
    const next = (modulo: number): number => {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      return (state >>> 8) % modulo;
    };

    const memory = memoryRateLimitStore();
    const server = live(a, "random");
    let clock = 1_000_000;
    let refusals = 0;

    for (let i = 0; i < 400; i++) {
      const request = { limit: 1 + next(6), windowMs: 1_000 + next(59_000), now: (clock += next(3_000)) };
      const bucket = `acct:${next(4)}`;

      const expected = await memory.hit(bucket, request);
      if (!expected.allowed) refusals++;
      expectSameVerdict(await server.hit(bucket, request), expected, `#${i}`);
    }

    expect(refusals).toBeGreaterThan(0);
  });

  test("a burst fired at once admits exactly the limit, through a real server", async () => {
    // The single-key atomicity claim. `connectRedis` carries one command at a time
    // on one connection and the middleware sends exactly one per request, so 512
    // requests in flight on it is the real shape of a gateway burst rather than a
    // synthetic one. A read-then-write script — GET, yield, SET — admits all 512.
    const server = live(a, "burst");
    const limit = 128;
    const request = { limit, windowMs: WINDOW_MS, now: 0 };

    const verdicts = await Promise.all(Array.from({ length: 512 }, () => server.hit("burst", request)));

    expect(verdicts.filter((v) => v.allowed)).toHaveLength(limit);
    expect(verdicts.filter((v) => !v.allowed)).toHaveLength(512 - limit);
  });

  test("two stores on two separate connections share one bucket; two memory stores do not", async () => {
    // The property the Redis backend exists for, and the v0 hole it plugs, stated
    // against two real sockets rather than one fake. If the counter lived in either
    // process this would be two allowances of two, and the memory half below is
    // what says so.
    const first = live(a, "replica");
    const second = live(b, "replica");
    const limit = 2;
    const request = { limit, windowMs: WINDOW_MS, now: 0 };

    expect((await first.hit("acct:1", request)).allowed).toBe(true);
    expect((await second.hit("acct:1", request)).allowed).toBe(true);
    expect((await first.hit("acct:1", request)).allowed).toBe(false);
    expect((await second.hit("acct:1", request)).allowed).toBe(false);

    const localA = memoryRateLimitStore();
    const localB = memoryRateLimitStore();
    expect((await localA.hit("acct:1", request)).allowed).toBe(true);
    expect((await localA.hit("acct:1", request)).allowed).toBe(true);
    expect((await localA.hit("acct:1", request)).allowed).toBe(false);
    expect((await localB.hit("acct:1", request)).allowed).toBe(true);
  });

  test("two accounts' buckets are separate keys against a real server", async () => {
    // The tenant boundary, where it is actually load-bearing. Everything else in
    // this file proves the script counts correctly; this proves it counts the
    // *right things* — that exhausting one account's allowance leaves another's
    // untouched, and that neither key holds the other's identity.
    //
    // `tenantIsolation.test.ts` covers the same property against the in-memory
    // store and against the client half of this one, over a transcription of the
    // script. A transcription cannot be wrong in the same way as the script, so
    // this is the tier where "two accounts do not share a bucket" is a fact about
    // Redis rather than a fact about our reading of Redis.
    const store = live(a, "tenants");
    const limit = 2;
    const request = { limit, windowMs: WINDOW_MS, now: 0 };
    const bucketA = "acct:A";
    const bucketB = "acct:B";

    for (let i = 0; i < limit; i++) expect((await store.hit(bucketA, request)).allowed).toBe(true);

    // A is exhausted...
    expect((await store.hit(bucketA, request)).allowed).toBe(false);
    // ...and B, which sent nothing, has its whole allowance. The denial-of-service
    // direction: a shared bucket would let one account throttle another.
    expect((await store.hit(bucketB, request)).allowed).toBe(true);
    expect((await store.hit(bucketB, request)).allowed).toBe(true);
    expect((await store.hit(bucketB, request)).allowed).toBe(false);

    // Two keys, and neither names an account in the clear — the digest in
    // `bucket()` means a `KEYS guard:rl:*` scan yields no list of the accounts
    // hitting the edge. `written` holds both because `live()` records them.
    expect(written.has(store.keyFor(bucketA))).toBe(true);
    expect(written.has(store.keyFor(bucketB))).toBe(true);
    expect(store.keyFor(bucketA)).not.toBe(store.keyFor(bucketB));
  });

  test("a bucket survives losing the connection it was counted in", async () => {
    // Restart is the other half of "per process": every in-memory bucket is lost
    // on restart, so a deploy is a fresh allowance for every caller at once. Redis
    // is the only reason that is not true, and only a real server can show it.
    const before = live(a, "survives");
    expect((await before.hit("acct:1", { limit: 1, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);

    const after = live(b, "survives");
    expect((await after.hit("acct:1", { limit: 1, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(false);
  });

  test("the script expires its own key, so a bucket is not kept forever", async () => {
    // A Redis that accumulates a bucket for every client that has ever connected is
    // a memory leak with a business-sized keyspace, and the only thing standing
    // between that and production is the `PX` on the `SET` inside the script. Read
    // it back from the server rather than from the transcription of the script.
    const store = live(a, "ttl");
    const key = store.keyFor("acct:1");

    await store.hit("acct:1", { limit: 4, windowMs: WINDOW_MS, now: 0 });
    const ttl = await call(a, "return redis.call('TTL', KEYS[1])", key);

    expect(typeof ttl).toBe("number");
    expect(ttl as number).toBeGreaterThan(0);
    expect(ttl as number).toBeLessThanOrEqual(Math.ceil(WINDOW_MS / 1000));
  });

  test("a refused request leaves the stored debt where an admitted one left it", async () => {
    // Read back through the server, so this is what Redis *holds* rather than what
    // the client was told. The refusal branch writes nothing, and a version that
    // did would let a caller that keeps hammering while throttled lock itself out
    // for as long as it keeps trying.
    const store = live(a, "debt");
    const key = store.keyFor("acct:1");
    const limit = 3;
    const request = { limit, windowMs: WINDOW_MS, now: 0 };

    for (let i = 0; i < limit; i++) await store.hit("acct:1", request);
    const admitted = await call(a, "return redis.call('GET', KEYS[1])", key);

    for (let i = 0; i < 20; i++) expect((await store.hit("acct:1", request)).allowed).toBe(false);
    const refused = await call(a, "return redis.call('GET', KEYS[1])", key);

    expect(refused).toBe(admitted);
  });

  test("the store's bucket charset is enforced against a real server, not only in a fake", async () => {
    // A key that trips the store's own check throws, and the middleware fails open
    // on that throw — so a deployment with a bad bucket name has a limiter that is
    // silently off. Asserting it throws is what keeps that visible.
    const store = live(a, "charset");
    await expect(store.hit("a b c", { limit: 1, windowMs: WINDOW_MS, now: 0 })).rejects.toThrow(RangeError);
    await expect(store.hit("x".repeat(129), { limit: 1, windowMs: WINDOW_MS, now: 0 })).rejects.toThrow(RangeError);
  });
});
