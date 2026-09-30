// The distributed half of the limiter.
//
// Two deployments exist and the operator picks: `memoryRateLimitStore` for one
// instance, this for several. The counter lives in Redis, so every replica
// shares one allowance and nothing is lost on restart — which is the whole reason
// this file exists.
//
// Three deliberate constraints, in order of how much they cost to get wrong:
//
//   1. The count is one Lua script, not a GET followed by a SET. A read-then-write
//      limiter admits N times the limit under a burst, and a burst is exactly
//      what an edge receives.
//   2. The script expires its own key (`PX`). A Redis that accumulates a bucket
//      for every client that has ever connected is a memory leak with a
//      business-sized keyspace.
//   3. The transport is a port (`RedisCommands`), not a socket baked in. That is
//      what lets `rateLimitParity.test.ts` drive this store over a fake and
//      assert it behaves identically to the in-memory one — with no server, no
//      socket and no network anywhere in the suite.
//
// What the suite does NOT do is execute the Lua. `rateLimitRedis.test.ts` carries
// a line-for-line transcription of the script and the parity table runs against
// the Redis path through it, so the client-side code (key names, argument
// marshalling, reply decoding) is executed and covered; the script body itself is
// covered by review. TODO(guard-06): run it against a real redis-server in the
// deploy pipeline.
import { assertPositiveInteger } from "./assert";
import type { RateLimitStore, RateLimitRequest, Verdict } from "./rateLimitTypes";

/**
 * The whole Redis surface this repository needs: one script and one ping.
 *
 * Deliberately not a general client. Every method added here is a method the
 * RESP transport below has to grow and the fake in the tests has to implement.
 */
export interface RedisCommands {
  /**
   * `EVAL script numkeys key… arg…`.
   *
   * Returns whatever the script returns. The store checks the shape of that
   * answer rather than trusting it: a Redis that answers `-ERR` (a Lua
   * environment that cannot run the script, a renamed command) must surface as
   * an error, not as an open bucket.
   */
  eval(script: string, keys: string[], args: string[]): Promise<unknown>;
  /** `PING`, for the readiness probe. */
  ping(): Promise<boolean>;
}

/**
 * GCRA, as one atomic step.
 *
 * The same algorithm as `count()` in `rateLimitStore.ts`, held to it by
 * `rateLimitParity.test.ts`. `KEYS[1]` is the whole client namespace —
 * `bucket:account:…` — so two policies never share a bucket by accident, and
 * the script stays a single-key operation, which is what lets Redis run it on
 * the shard that holds it.
 *
 * Returns `{allowed, resetAt, retryAt, remaining}`, all epoch milliseconds or a
 * count — the same units `Verdict` uses, so no conversion happens anywhere else.
 */
export const GCRA_LUA = `
local tat = tonumber(redis.call('GET', KEYS[1]) or '0')
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local interval = window / limit
local next = math.max(now, tat) + interval
local delay = next - now
if delay > window then return {0, tat, next - window, 0} end
redis.call('SET', KEYS[1], next, 'PX', window)
local used = math.ceil((next - now) / interval)
return {1, next, next - interval - window, math.max(0, limit - used)}
`;

export type RedisRateLimitStoreOptions = {
  commands: RedisCommands;
  /**
   * Sub-namespace, so two guards (or two environments) sharing one Redis do not
   * read each other's buckets. It is *added to* guard's own namespace rather
   * than replacing it: a key outside `guard:rl` is a key nobody can find again
   * with `KEYS`, and a bucket namespace an operator can typo away is a bucket
   * namespace that silently stops limiting. Constrained to the base64url
   * alphabet because it ends up in a Redis key.
   */
  prefix?: string;
};

const NAMESPACE = "guard:rl";

export type RedisRateLimitStore = RateLimitStore & {
  /** The Redis key a bucket lives in. v0 introspection, off the trait. */
  keyFor(bucket: string): string;
};

/**
 * Counts buckets in Redis.
 *
 * One `EVAL` per request and nothing else: the round trip is the latency a
 * gateway pays on every single call, and splitting it into a read and a write
 * doubles that and breaks atomicity at the same time.
 */
export function redisRateLimitStore(options: RedisRateLimitStoreOptions): RedisRateLimitStore {
  const { commands } = options;
  const prefix = options.prefix === undefined ? NAMESPACE : `${NAMESPACE}:${parsePrefix(options.prefix)}`;

  const keyFor = (bucket: string): string => `${prefix}:${assertBucket(bucket)}`;

  return {
    keyFor,

    async hit(bucket: string, request: RateLimitRequest): Promise<Verdict> {
      const reply = await commands.eval(
        GCRA_LUA,
        [keyFor(bucket)],
        [String(request.limit), String(request.windowMs), String(request.now)],
      );

      return verdictOf(reply);
    },
  };
}

/**
 * The script's answer, or an error.
 *
 * The shape check comes first, before any numeric coercion: a table of the
 * wrong arity, or a nil, has told us nothing about whether the caller was
 * admitted, and inferring `allowed` from it is how a limiter opens without
 * anybody noticing.
 */
function verdictOf(reply: unknown): Verdict {
  if (!Array.isArray(reply) || reply.length !== 4) {
    throw new Error(`guard: the rate-limit script answered ${JSON.stringify(reply)}`);
  }

  const numbers = reply.map((part) => {
    const value = Number(part);
    if (!Number.isFinite(value)) {
      throw new Error(`guard: the rate-limit script answered a non-number in ${JSON.stringify(reply)}`);
    }
    return value;
  });

  const [allowed, resetAt, retryAt, remaining] = numbers as [number, number, number, number];

  return { allowed: allowed === 1, remaining, resetAt, retryAt };
}

const BUCKET = /^[A-Za-z0-9_.:-]{1,128}$/;

function assertBucket(value: string): string {
  if (typeof value !== "string" || !BUCKET.test(value)) {
    throw new RangeError(
      `redisRateLimitStore: bucket must match [A-Za-z0-9_.:-]{1,128}, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

function parsePrefix(value: string): string {
  if (typeof value !== "string" || !BUCKET.test(value)) {
    throw new RangeError(
      `redisRateLimitStore: prefix must match [A-Za-z0-9_.:-]{1,128}, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}
// ---------------------------------------------------------------- transport

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * RESP2 command encoding.
 *
 * Pure, and tested without a socket, because getting a byte count wrong is the
 * classic way a hand-rolled client corrupts a command in a way that reads as a
 * server fault rather than a client fault.
 */
export function encodeCommand(args: string[]): Uint8Array {
  if (args.length === 0) throw new RangeError("encodeCommand: a command needs at least a name");

  const parts: string[] = [`*${args.length}\r\n`];
  for (const arg of args) {
    parts.push(`$${encoder.encode(arg).byteLength}\r\n`, arg, "\r\n");
  }

  return encoder.encode(parts.join(""));
}

export type RespValue = string | number | RespValue[] | null;

/**
 * RESP2 reply parsing: one value, and how many bytes it used.
 *
 * An error reply throws. `-ERR` from `EVAL` means the script did not run, and
 * treating that as "no quota used" is a limiter that is open exactly when the
 * thing it depends on is broken.
 */
export function parseReply(bytes: Uint8Array, at = 0): { value: RespValue; read: number } {
  const marker = bytes[at];
  const line = readLine(bytes, at);

  switch (marker) {
    case 0x2b: // '+' simple string
      return { value: line, read: line.length + 3 };
    case 0x2d: // '-' error
      throw new Error(`guard: redis said ${line}`);
    case 0x3a: // ':' integer
      return { value: integer(line), read: line.length + 3 };
    case 0x24: {
      // '$' bulk string
      const length = integer(line);
      if (length < 0) return { value: null, read: line.length + 3 };

      const start = at + line.length + 3;
      if (start + length + 2 > bytes.byteLength) throw new Error("guard: redis sent a truncated reply");

      return { value: decoder.decode(bytes.subarray(start, start + length)), read: line.length + 3 + length + 2 };
    }
    case 0x2a: {
      // '*' array
      const length = integer(line);
      if (length < 0) return { value: null, read: line.length + 3 };

      const items: RespValue[] = [];
      let cursor = at + line.length + 3;
      for (let i = 0; i < length; i++) {
        const item = parseReply(bytes, cursor);
        items.push(item.value);
        cursor += item.read;
      }
      return { value: items, read: cursor - at };
    }
    default:
      throw new Error(`guard: redis sent an unknown reply type ${JSON.stringify(String(marker ?? ""))}`);
  }
}

/** The text after the marker, up to and including the CRLF. */
function readLine(bytes: Uint8Array, at: number): string {
  for (let i = at + 1; i < bytes.length - 1; i++) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a) return decoder.decode(bytes.subarray(at + 1, i));
  }
  throw new Error("guard: redis sent a truncated reply");
}

function integer(line: string): number {
  const value = Number(line);
  if (!Number.isInteger(value)) {
    throw new Error(`guard: redis sent ${JSON.stringify(line)} where a whole number was due`);
  }
  return value;
}

// -------------------------------------------------------------- the socket

export type RedisConnectionOptions = {
  /** `redis://host:port`, or `rediss://` for TLS. No path, no database number. */
  url: string;
  /** How long one command may take before it is abandoned. Default 2000. */
  timeoutMs?: number;
};

const DEFAULT_TIMEOUT_MS = 2_000;

/**
 * A RESP connection to Redis.
 *
 * Deliberately the smallest thing that works: `EVAL` and `PING`, one command in
 * flight at a time, a deadline on every operation. A general-purpose Redis
 * client would be a dependency this repository does not have, and the reason is
 * in README.md — this is forty lines of RESP2, and the client half of it is
 * covered by the pure `encodeCommand`/`parseReply` tests above.
 *
 * The socket itself is the one part of this backend the suite does not execute.
 * TODO(guard-06) as at the top of the file.
 */
export async function connectRedis(options: RedisConnectionOptions): Promise<RedisCommands & { close(): void }> {
  const target = parseRedisUrl(options.url);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  assertPositiveInteger(timeoutMs, "timeoutMs");

  /** Replies not yet claimed by a caller, oldest first. */
  const pending: RespValue[] = [];
  /** Callers waiting for a reply, oldest first. */
  const waiting: Array<(value: RespValue) => void> = [];
  let buffered: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let broken: Error | null = null;

  const fail = (error: Error): void => {
    broken = error;
    while (waiting.length > 0) waiting.shift()?.(null as never);
  };

  const drain = (): void => {
    for (;;) {
      let parsed: { value: RespValue; read: number };
      try {
        parsed = parseReply(buffered);
      } catch {
        // Either more bytes are needed or the stream is nonsense; the socket
        // handlers tell the two apart, and neither can be acted on here.
        return;
      }

      buffered = buffered.subarray(parsed.read);
      pending.push(parsed.value);

      const resolve = waiting.shift();
      if (resolve === undefined) continue;
      resolve(pending.shift() ?? null);
    }
  };

  // `await` because Bun's own types declare this as a promise, and a socket is
  // not a thenable, so awaiting a value that arrived synchronously costs one
  // microtask and is correct under either shape.
  const socket = await Bun.connect({
    hostname: target.hostname,
    port: target.port,
    ...(target.tls ? { tls: {} } : {}),
    socket: {
      data(_socket, chunk) {
        buffered = concat(buffered, chunk);
        drain();
      },
      error(_socket, error) {
        fail(error instanceof Error ? error : new Error(String(error)));
      },
      close() {
        fail(new Error("guard: the redis connection closed"));
      },
    },
  });

  const send = (args: string[]): Promise<RespValue> =>
    within(
      new Promise<RespValue>((resolve) => {
        if (broken !== null) {
          resolve(null as never);
          return;
        }
        waiting.push(resolve);
        socket.write(encodeCommand(args));
      }),
      timeoutMs,
      args[0] ?? "COMMAND",
    );

  return {
    async eval(script, keys, args) {
      return send(["EVAL", script, String(keys.length), ...keys, ...args]);
    },

    async ping() {
      return (await send(["PING"])) === "PONG";
    },

    close() {
      socket.close();
    },
  };
}

/**
 * A connection that opens on first use.
 *
 * `runtimeOptions` is synchronous and `Bun.connect` is not, so the connection is
 * deferred rather than awaited. Two things follow, and both are deliberate:
 *
 *   * A malformed URL is still a startup error. The URL is parsed here, eagerly,
 *     because `REDIS_URL=redis//redis` should not wait for the first request to
 *     discover it.
 *   * A Redis that is *down* is not a startup error. The store fails open until
 *     the socket answers and `/readyz` reports `redis: unavailable` meanwhile.
 *     A gateway that refuses to boot because its counter store is down has turned
 *     someone else's outage into its own.
 *
 * A failed attempt is not cached, so the next request retries: an outage that
 * ends is an outage a long-lived process recovers from rather than one it
 * remembers forever.
 */
export function lazyRedis(options: RedisConnectionOptions): RedisCommands & { close(): void } {
  // Parsed and discarded: the point is that a malformed URL throws HERE, at
  // construction, and not later on the first request.
  parseRedisUrl(options.url);
  let connection: (RedisCommands & { close(): void }) | null = null;
  let opening: Promise<RedisCommands & { close(): void }> | null = null;

  const open = (): Promise<RedisCommands & { close(): void }> => {
    if (connection) return Promise.resolve(connection);

    opening ??= connectRedis({ url: options.url, timeoutMs: options.timeoutMs }).then(
      (opened) => {
        connection = opened;
        opening = null;
        return opened;
      },
      (error: unknown) => {
        opening = null;
        throw error;
      },
    );

    return opening;
  };

  return {
    async eval(script, keys, args) {
      return (await open()).eval(script, keys, args);
    },

    async ping() {
      return (await open()).ping();
    },

    close() {
      connection?.close();
      connection = null;
      opening = null;
    },
  };
}

function concat(into: Uint8Array, more: Uint8Array): Uint8Array {  const joined = new Uint8Array(into.byteLength + more.byteLength);
  joined.set(into, 0);
  joined.set(more, into.byteLength);
  return joined;
}

/**
 * `redis://` or `rediss://`, host and port, no path.
 *
 * The path is refused rather than ignored: the quietest way to lose every bucket
 * is to write to database 0 and read from database 1, and a URL that quietly
 * accepted `/1` would do exactly that.
 */
function parseRedisUrl(value: string): { hostname: string; port: number; tls: boolean } {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RangeError(`connectRedis: url must be a redis:// URL, got ${JSON.stringify(value)}`);
  }

  if (url.protocol !== "redis:" && url.protocol !== "rediss:") {
    throw new RangeError(`connectRedis: url must be redis:// or rediss://, got ${JSON.stringify(value)}`);
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new RangeError(`connectRedis: url must have no path, got ${JSON.stringify(value)}`);
  }

  const port = Number(url.port || 6379);
  assertPositiveInteger(port, "connectRedis: port");

  return { hostname: url.hostname, port, tls: url.protocol === "rediss:" };
}

/** A promise bounded in time. See `bff/auth.ts` for why both halves are needed. */
async function within<T>(work: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expiry = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`redis ${what} did not answer within ${ms}ms`)), ms);
  });

  try {
    return await Promise.race([work, expiry]);
  } finally {
    clearTimeout(timer);
  }
}
