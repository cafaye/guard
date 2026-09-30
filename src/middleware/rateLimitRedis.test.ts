import { describe, expect, test } from "bun:test";
import {
  encodeCommand,
  GCRA_LUA,
  parseReply,
  redisRateLimitStore,
  type RedisCommands,
} from "./rateLimitRedis";

const WINDOW_MS = 60_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * A stand-in for Redis that runs the GCRA script's own algorithm.
 *
 * It exists so the suite can prove that the Redis store — its key names, the
 * arguments it marshals, the shape of the reply it decodes — behaves exactly
 * like the in-memory store, with no server and no socket. It is a fake for the
 * *transport*, not for the arithmetic: `runScript` below is a line-for-line
 * transcription of GCRA_LUA, and `rateLimitParity.test.ts` runs both stores
 * over the same table.
 *
 * The script body itself is executed by `rateLimitRedisLive.test.ts`, against a
 * real redis-server, in the `redis` CI job. This file stays the one that needs
 * no server, so `bin/prime` is hermetic.
 */
function fakeRedis(): RedisCommands & { calls: Array<{ key: string; args: string[] }>; size(): number } {
  const keys = new Map<string, number>();
  const calls: Array<{ key: string; args: string[] }> = [];

  return {
    calls,
    async eval(script, keysIn, args) {
      if (script !== GCRA_LUA) throw new Error("unexpected script");
      if (keysIn.length !== 1) throw new Error("expected exactly one key");

      const key = keysIn[0] ?? "";
      calls.push({ key, args });

      // --- GCRA_LUA, line for line -----------------------------------------
      // local tat = tonumber(redis.call('GET', KEYS[1]) or '0')
      const tat = keys.get(key) ?? 0;
      const limit = Number(args[0]);
      const windowMs = Number(args[1]);
      const now = Number(args[2]);
      // local interval = window / limit
      const interval = windowMs / limit;
      // local next = math.max(now, tat) + interval
      const next = Math.max(now, tat) + interval;
      // local delay = next - now
      const delay = next - now;
      // if delay > window then return {0, tat, next - window, 0} end
      if (delay > windowMs) return [0, tat, next - windowMs, 0];
      // redis.call('SET', KEYS[1], next, 'PX', window)
      keys.set(key, next);
      // local used = math.ceil((next - now) / interval)
      const used = Math.ceil((next - now) / interval);
      // return {1, next, next - interval - window, math.max(0, limit - used)}
      return [1, next, next - interval - windowMs, Math.max(0, limit - used)];
      // ---------------------------------------------------------------------
    },
    async ping() {
      return true;
    },
    size: () => keys.size,
  };
}

describe("redisRateLimitStore", () => {
  test("admits exactly `limit` and refuses the one after", async () => {
    const store = redisRateLimitStore({ commands: fakeRedis() });

    for (let i = 0; i < 4; i++) {
      expect((await store.hit("acct:1", { limit: 4, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(true);
    }

    expect((await store.hit("acct:1", { limit: 4, windowMs: WINDOW_MS, now: 0 })).allowed).toBe(false);
  });

  test("namespaces its keys so one guard cannot read another's buckets", async () => {
    const commands = fakeRedis();
    await redisRateLimitStore({ commands, prefix: "edge-a" }).hit("acct:1", {
      limit: 1,
      windowMs: WINDOW_MS,
      now: 0,
    });

    expect(commands.calls[0]?.key).toBe("guard:rl:edge-a:acct:1");
  });

  test("defaults the namespace to guard's own", async () => {
    const commands = fakeRedis();
    await redisRateLimitStore({ commands }).hit("acct:1", { limit: 1, windowMs: WINDOW_MS, now: 0 });

    expect(commands.calls[0]?.key).toBe("guard:rl:acct:1");
  });

  test("passes limit, window and now as whole-millisecond integers", async () => {
    const commands = fakeRedis();
    await redisRateLimitStore({ commands }).hit("acct:1", {
      limit: 7,
      windowMs: 1_000,
      now: 1_764_000_000_123,
    });

    expect(commands.calls[0]?.args).toEqual(["7", "1000", "1764000000123"]);
  });

  test("refuses a prefix that is not a plain token", () => {
    const commands = fakeRedis();
    expect(() => redisRateLimitStore({ commands, prefix: "a b" })).toThrow(RangeError);
    expect(() => redisRateLimitStore({ commands, prefix: "" })).toThrow(RangeError);
  });

  test("the Lua it runs is a single self-contained script with one key", () => {
    // The atomicity of the whole limiter rests on this being one script: a
    // read-then-write pair is what admits N times the limit under a burst.
    expect(GCRA_LUA).toContain("redis.call('GET', KEYS[1])");
    expect(GCRA_LUA).toContain("redis.call('SET', KEYS[1]");
    expect(GCRA_LUA).toContain("'PX'");
    // It must expire its own key, or a Redis deployment accumulates a bucket
    // for every client that has ever connected. And one branch, because one
    // branch is the whole claim: a script with a second `if` is a script whose
    // decision is harder to read off than its answer.
    const lines = GCRA_LUA.split("\n").map((line) => line.trim()).filter(Boolean);
    expect(lines.filter((line) => line.startsWith("if "))).toHaveLength(1);
  });

  test("a reply that is not the shape the script promises is refused, not guessed at", async () => {
    const lying: RedisCommands = {
      eval: () => Promise.resolve(["nope", "0", "0", "0"]),
      ping: () => Promise.resolve(true),
    };

    await expect(lying.eval(GCRA_LUA, ["k"], ["1", "1000", "0"])).resolves.toBeDefined();
    // The store's own decoding is what has to be defensive; drive it directly.
    const store = redisRateLimitStore({ commands: lying });
    await expect(store.hit("k", { limit: 1, windowMs: 1000, now: 0 })).rejects.toThrow();
  });
});

describe("RESP encoding", () => {
  test("writes a command as an array of bulk strings", () => {
    const written = decoder.decode(encodeCommand(["GET", "guard:rl:k"]));

    expect(written).toBe("*2\r\n$3\r\nGET\r\n$10\r\nguard:rl:k\r\n");
  });

  test("counts bytes, not characters, for a multi-byte argument", () => {
    // A length computed in characters would truncate the command and Redis
    // would read the tail as the next bulk header.
    const written = encodeCommand(["SET", "k", "é"]);

    expect(decoder.decode(written)).toBe("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$2\r\né\r\n");
  });

  test("refuses an empty command, which RESP cannot express", () => {
    expect(() => encodeCommand([])).toThrow(RangeError);
  });
});

describe("RESP reply parsing", () => {
  // `parseReply` reports how many bytes it used, because the socket reader has to
  // resume after them; a test that only wants the value says so here.
  const parse = (text: string) => parseReply(encoder.encode(text)).value;

  test("reads an integer reply", () => {
    expect(parse(":42\r\n")).toEqual(42);
  });

  test("reads a bulk string reply", () => {
    expect(parse("$5\r\nhello\r\n")).toEqual("hello");
  });

  test("reads an array reply", () => {
    expect(parse("*2\r\n:1\r\n$3\r\nabc\r\n")).toEqual([1, "abc"]);
  });

  test("reads a nil array, which is how an absent key answers", () => {
    expect(parse("*-1\r\n")).toBeNull();
  });

  test("reads a nil bulk string", () => {
    expect(parse("$-1\r\n")).toBeNull();
  });

  test("reads a simple string", () => {
    expect(parse("+PONG\r\n")).toEqual("PONG");
  });

  test("an error reply is an error, not a value", () => {
    // Redis answering `-ERR ...` for a script that is present is a real
    // failure mode (a wrong Lua version, a renamed command). Swallowing it
    // would make the limiter look open when Redis is refusing to run it.
    expect(() => parse("-ERR unknown command\r\n")).toThrow(/unknown command/);
  });

  test("a truncated reply is an error rather than a half-read value", () => {
    expect(() => parse("$5\r\nhel")).toThrow();
    expect(() => parse("*2\r\n:1\r\n")).toThrow();
  });

  test("an unknown type byte is an error", () => {
    expect(() => parse("%1\r\n")).toThrow();
  });
});
