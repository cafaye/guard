import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { rateLimit } from "./rateLimit";

const WINDOW_MS = 60_000;

// Windows are aligned to the wall clock, so the window containing 1_000_000
// starts at 960_000 and ends at 1_020_000 — not at 1_000_000 + WINDOW_MS. Every
// timing below is written against these two instants, because "the last
// millisecond of this window" and "when the allowance comes back" are both
// properties of the aligned window, not of the clock reading that made the
// request.
const WINDOW_START = 960_000;
const WINDOW_END = WINDOW_START + WINDOW_MS;

function app(opts: { limit: number; now: () => number }) {
  const a = new Hono();
  a.use(
    "*",
    rateLimit({
      limit: opts.limit,
      windowMs: WINDOW_MS,
      keyGenerator: (c) => c.req.header("x-client") ?? "client-a",
      now: opts.now,
    }),
  );
  a.get("/", (c) => c.json({ ok: true }));
  return a;
}

describe("rateLimit fixed window", () => {
  test("allows requests up to the limit, then rejects with 429", async () => {
    let now = 1_000_000;
    const a = app({ limit: 2, now: () => now });

    expect((await a.request("/")).status).toBe(200);
    expect((await a.request("/")).status).toBe(200);

    const blocked = await a.request("/");
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("content-type")).toContain("application/json");
    expect(await blocked.json()).toEqual({
      error: "rate_limited",
      message: "too many requests",
    });
  });

  test("stays rejected for the rest of the window", async () => {
    let now = 1_000_000;
    const a = app({ limit: 1, now: () => now });

    expect((await a.request("/")).status).toBe(200);
    expect((await a.request("/")).status).toBe(429);

    // One millisecond before the window rolls over.
    now = WINDOW_END - 1;
    expect((await a.request("/")).status).toBe(429);
  });

  test("counts reset when a new window starts", async () => {
    let now = 1_000_000;
    const a = app({ limit: 1, now: () => now });

    expect((await a.request("/")).status).toBe(200);
    expect((await a.request("/")).status).toBe(429);

    now = 1_000_000 + WINDOW_MS;
    expect((await a.request("/")).status).toBe(200);
  });

  test("windows are aligned to the wall clock, not to the first request", async () => {
    let now = 1_000_000; // window starts at 960_000
    const a = app({ limit: 1, now: () => now });

    expect((await a.request("/")).status).toBe(200);

    // Step into the next window and use it up.
    now = 1_000_000 + WINDOW_MS;
    expect((await a.request("/")).status).toBe(200);
    expect((await a.request("/")).status).toBe(429);

    // Go back to the earlier wall clock: that earlier window is spent too.
    now = 1_000_000;
    expect((await a.request("/")).status).toBe(429);
  });

  test("keys are isolated from each other", async () => {
    let now = 1_000_000;
    const a = app({ limit: 1, now: () => now });

    expect((await a.request("/", { headers: { "x-client": "a" } })).status).toBe(200);
    expect((await a.request("/", { headers: { "x-client": "a" } })).status).toBe(429);
    expect((await a.request("/", { headers: { "x-client": "b" } })).status).toBe(200);
  });

  test("reports limit, remaining and reset on allowed requests", async () => {
    let now = 1_000_000;
    const a = app({ limit: 3, now: () => now });

    const first = await a.request("/");
    expect(first.headers.get("X-RateLimit-Limit")).toBe("3");
    expect(first.headers.get("X-RateLimit-Remaining")).toBe("2");
    expect(Number(first.headers.get("X-RateLimit-Reset"))).toBe(WINDOW_END);

    const second = await a.request("/");
    expect(second.headers.get("X-RateLimit-Remaining")).toBe("1");
  });

  test("reports limit, remaining and reset on rejected requests", async () => {
    let now = 1_000_000;
    const a = app({ limit: 1, now: () => now });

    await a.request("/");
    const blocked = await a.request("/");

    expect(blocked.headers.get("X-RateLimit-Limit")).toBe("1");
    expect(blocked.headers.get("X-RateLimit-Remaining")).toBe("0");
    expect(Number(blocked.headers.get("X-RateLimit-Reset"))).toBe(WINDOW_END);
  });

  test("the reset instant is the aligned window end, not one window from now", async () => {
    let now = 1_000_000; // 40s into the window that opened at 960_000
    const a = app({ limit: 2, now: () => now });

    const res = await a.request("/");
    const reset = Number(res.headers.get("X-RateLimit-Reset"));

    // A client that trusted "one window from now" would sit idle for 40s after
    // the allowance was already back.
    expect(reset).toBe(WINDOW_END);
    expect(reset).toBeLessThan(now + WINDOW_MS);
  });

  test("a 429 says how long to wait, and the wait is not longer than the window", async () => {
    let now = 1_000_000;
    const a = app({ limit: 1, now: () => now });

    await a.request("/");
    const blocked = await a.request("/");

    const retryAfter = Number(blocked.headers.get("Retry-After"));
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(WINDOW_MS / 1000);
  });

  test("maxClients bounds the map by dropping spent windows", async () => {
    let now = 1_000_000;
    const a = new Hono();
    a.use(
      "*",
      rateLimit({
        limit: 1,
        windowMs: WINDOW_MS,
        maxClients: 2,
        keyGenerator: (c) => c.req.header("x-client") ?? "a",
        now: () => now,
      }),
    );
    a.get("/", (c) => c.json({ ok: true }));

    expect((await a.request("/", { headers: { "x-client": "a" } })).status).toBe(200);
    expect((await a.request("/", { headers: { "x-client": "a" } })).status).toBe(429);

    // Two windows later, with more clients than the cap: the sweep drops what
    // "a" and "b" spent to keep the map bounded.
    now = 1_000_000 + 2 * WINDOW_MS;
    for (const client of ["b", "c", "d"]) {
      await a.request("/", { headers: { "x-client": client } });
    }

    // Step back into the window "a" had spent and it is allowed again. That is
    // the price of the cap, and the reason the default is high enough that one
    // client cannot reach it: the retained-window behaviour the earlier test
    // pins only holds while nothing has been swept.
    now = 1_000_000;
    expect((await a.request("/", { headers: { "x-client": "a" } })).status).toBe(200);
  });

  test("rejects a limit below one at construction time", () => {
    const keyGenerator = () => "a";
    expect(() => rateLimit({ limit: 0, windowMs: WINDOW_MS, keyGenerator })).toThrow();
    expect(() => rateLimit({ limit: 1.5, windowMs: WINDOW_MS, keyGenerator })).toThrow();
  });

  test("rejects a window below one millisecond at construction time", () => {
    expect(() => rateLimit({ limit: 1, windowMs: 0, keyGenerator: () => "a" })).toThrow();
  });
});
