import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { requireJwt } from "./jwt";

// The stub only proves the guard is mounted: presence of an Authorization
// header, 401 without one. Real JWKS verification is a later packet.
function app() {
  const a = new Hono();
  a.use("/private/*", requireJwt());
  a.get("/private/thing", (c) => c.json({ ok: true }));
  return a;
}

describe("requireJwt (stub)", () => {
  test("401 when the Authorization header is absent", async () => {
    const res = await app().request("/private/thing");

    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({
      error: "unauthorized",
      message: "missing Authorization header",
    });
  });

  test("401 when the Authorization header is present but empty", async () => {
    const res = await app().request("/private/thing", {
      headers: { Authorization: "" },
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      error: "unauthorized",
      message: "missing Authorization header",
    });
  });

  test("401 body is JSON on every rejection shape", async () => {
    const res = await app().request("/private/thing", {
      headers: { Authorization: "   " },
    });

    expect(res.status).toBe(401);
    const body = (await res.json()) as { error?: unknown };
    expect(typeof body.error).toBe("string");
  });

  test("passes the request through when a header is present", async () => {
    const res = await app().request("/private/thing", {
      headers: { Authorization: "Bearer not-yet-verified" },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  test("does not run for routes outside the mount path", async () => {
    const res = await app().request("/elsewhere");

    expect(res.status).toBe(404);
  });
});
