import { describe, expect, test } from "bun:test";
import { createApp, type ProbeStatus } from "./index";

describe("GET /healthz", () => {
  test("200 with the exact ok body", async () => {
    const res = await createApp().request("/healthz");

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ status: "ok" });
  });

  test("needs no Authorization header", async () => {
    expect((await createApp().request("/healthz")).status).toBe(200);
  });
});

describe("GET /readyz", () => {
  test("200 and a deps object when every probe reports ok", async () => {
    const app = createApp({ probes: { core: () => "ok", identity: () => "ok" } });

    const res = await app.request("/readyz");

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ deps: { core: "ok", identity: "ok" } });
  });

  test("v0 default: no probes means ready with an empty deps object", async () => {
    const res = await createApp().request("/readyz");

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ deps: {} });
  });

  test("503 when a probe reports a dependency as unavailable", async () => {
    const app = createApp({
      probes: { core: () => "ok", identity: async (): Promise<ProbeStatus> => "unavailable" },
    });

    const res = await app.request("/readyz");

    expect(res.status).toBe(503);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ deps: { core: "ok", identity: "unavailable" } });
  });

  test("503 when a probe throws", async () => {
    const app = createApp({
      probes: {
        core: () => {
          throw new Error("connection refused");
        },
      },
    });

    const res = await app.request("/readyz");

    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ deps: { core: "unavailable" } });
  });

  test("503 when a probe rejects", async () => {
    const app = createApp({ probes: { core: () => Promise.reject(new Error("timeout")) } });

    expect((await app.request("/readyz")).status).toBe(503);
  });
});

describe("app surface", () => {
  test("unknown routes are 404 JSON, not an unhandled throw", async () => {
    const res = await createApp().request("/nope");

    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ error: "not_found", message: "no such route" });
  });

  test("a throwing handler is a flat JSON 500 and leaks nothing to the caller", async () => {
    const app = createApp();
    // Routes can be added to the app the factory hands back, so the error path
    // is tested without the shipped app owning a route that always fails.
    app.get("/boom", () => {
      throw new Error("dial 10.0.0.5:5432: connection refused");
    });

    const res = await app.request("/boom");

    expect(res.status).toBe(500);
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({
      error: "internal_error",
      message: "unexpected server error",
    });
    // The address goes to the log, never to an unauthenticated caller.
    expect(body).not.toContain("10.0.0.5");
  });

  test("rate limiting never throttles the probe endpoints", async () => {
    const app = createApp({ rateLimit: { limit: 1, windowMs: 60_000 } });

    for (let i = 0; i < 5; i++) {
      expect((await app.request("/healthz")).status).toBe(200);
      expect((await app.request("/readyz")).status).toBe(200);
    }
  });
});
