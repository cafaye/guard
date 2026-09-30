import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { problem } from "./problem";

/** A context is all `problem` needs, so the test builds the smallest one. */
function context(url = "https://api.cafaye.com/v1/me") {
  const app = new Hono();
  app.get("/v1/me", (c) => problem(c, { status: 401, code: "unauthorized", detail: "a bearer token is required" }));
  app.get("/v1/other", (c) =>
    problem(c, { status: 503, code: "unavailable", detail: "the signing keys could not be retrieved" }),
  );
  return app;
}

describe("problem", () => {
  test("core's envelope, field for field", async () => {
    const res = await context().request("/v1/me");
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/problem+json");
    expect(body).toMatchObject({
      type: "https://errors.cafaye.com/unauthorized",
      title: "Unauthorized",
      status: 401,
      detail: "a bearer token is required",
      instance: "/v1/me",
      code: "unauthorized",
    });
  });

  test("trace_id is 32 hex characters and matches the X-Trace-Id header", async () => {
    const res = await context().request("/v1/me");
    const body = (await res.json()) as { trace_id: string };

    expect(body.trace_id).toMatch(/^[0-9a-f]{32}$/);
    expect(res.headers.get("x-trace-id")).toBe(body.trace_id);
  });

  test("two failures carry two ids, so support can tell them apart", async () => {
    const app = context();
    const first = await app.request("/v1/me");
    const second = await app.request("/v1/me");

    const a = first.headers.get("x-trace-id");
    const b = second.headers.get("x-trace-id");

    expect(a).not.toBe(b);
  });

  test("the code is the last segment of the type, and carries its own title", async () => {
    const res = await context().request("/v1/other");
    const body = (await res.json()) as { type: string; code: string; title: string; status: number };

    expect(res.status).toBe(503);
    expect(body.code).toBe("unavailable");
    expect(body.type).toBe(`https://errors.cafaye.com/${body.code}`);
    expect(body.title).toBe("Service unavailable");
  });

  test("instance is the request path, without the query string", async () => {
    const res = await context().request("/v1/me?token=secret");
    const body = (await res.json()) as { instance: string };

    // A token in a query string must not come back out in an error body.
    expect(body.instance).toBe("/v1/me");
  });
});
