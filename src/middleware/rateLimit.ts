import type { Context, MiddlewareHandler } from "hono";

export type RateLimitOptions = {
  /** Requests allowed per window. An integer >= 1. */
  limit: number;
  /** Window length in milliseconds. An integer >= 1. */
  windowMs: number;
  /**
   * Which client this counter belongs to. Required rather than defaulted: every
   * identifier a request carries is a header the caller chose, so a default here
   * would be a limit any caller can walk around by rotating one header.
   */
  keyGenerator: (c: Context) => string;
  /** Clock, injected so a test can cross a window boundary without sleeping. */
  now?: () => number;
  /**
   * Clients held in memory before spent windows are swept. Bounds the map in a
   * long-lived process; it is not a distributed cap and says nothing about
   * aggregate traffic.
   */
  maxClients?: number;
};

const DEFAULT_MAX_CLIENTS = 10_000;

/**
 * In-memory fixed-window rate limiter.
 *
 * STUB for v0. Per process, so a client gets `limit` per window from *each*
 * replica, and the counters are lost on restart. Redis-backed shared counting
 * is a later packet; until then this is honest about being one process's worth
 * of memory and no more.
 */
export function rateLimit(options: RateLimitOptions): MiddlewareHandler {
  const { limit, windowMs, keyGenerator, now = Date.now, maxClients = DEFAULT_MAX_CLIENTS } = options;

  assertPositiveInteger(limit, "limit");
  assertPositiveInteger(windowMs, "windowMs");

  /** client -> window start -> requests counted in that window. */
  const counters = new Map<string, Map<number, number>>();

  return async function rateLimitMiddleware(c, next) {
    const at = now();
    // Windows are aligned to the wall clock rather than started by the first
    // request a client happens to make, so every client shares one reset
    // instant and nobody can stretch a window by spacing requests out.
    const windowStart = Math.floor(at / windowMs) * windowMs;
    const windowEnd = windowStart + windowMs;

    const client = keyGenerator(c);
    if (counters.size >= maxClients) sweepSpentWindows(counters, at, windowMs);

    const windows = counters.get(client) ?? new Map<number, number>();
    const seen = (windows.get(windowStart) ?? 0) + 1;
    windows.set(windowStart, seen);
    counters.set(client, windows);

    c.header("X-RateLimit-Limit", String(limit));
    c.header("X-RateLimit-Remaining", String(Math.max(0, limit - seen)));
    // Absolute epoch milliseconds at which this window ends and the full
    // allowance is back — a fixed instant, not "one window from this request".
    c.header("X-RateLimit-Reset", String(windowEnd));

    if (seen > limit) {
      c.header("Retry-After", String(Math.ceil((windowEnd - at) / 1000)));
      return c.json({ error: "rate_limited", message: "too many requests" }, 429);
    }

    await next();
  };
}

/**
 * Drops windows that can no longer be counted against.
 *
 * A client's spent windows stay readable until they expire, which is what keeps
 * the limiter correct when the clock moves backwards: a counter that only
 * remembered "the current window" would hand out a fresh allowance for free
 * after a backwards step, and a backwards step is exactly what an NTP
 * correction looks like.
 */
function sweepSpentWindows(
  counters: Map<string, Map<number, number>>,
  at: number,
  windowMs: number,
): void {
  for (const [client, windows] of counters) {
    for (const start of windows.keys()) {
      if (start + windowMs <= at) windows.delete(start);
    }
    if (windows.size === 0) counters.delete(client);
  }
}

function assertPositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new RangeError(`rateLimit: ${field} must be an integer >= 1, got ${String(value)}`);
  }
}
