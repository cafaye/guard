import { describe, expect, test } from "bun:test";
import { DEFAULT_LIMIT_TABLE, resolveLimit, type LimitTable } from "./limits";

describe("the limit table", () => {
  test("every shipped entry is a whole number of requests over a whole second", () => {
    const entries = [DEFAULT_LIMIT_TABLE.default, ...Object.values(DEFAULT_LIMIT_TABLE.routes)];

    for (const entry of entries) {
      expect(Number.isInteger(entry.limit)).toBe(true);
      expect(entry.limit).toBeGreaterThan(0);
      expect(Number.isInteger(entry.windowMs)).toBe(true);
      expect(entry.windowMs).toBeGreaterThan(0);
      expect(entry.policy).toMatch(/^[a-z][a-z0-9-]*$/);
    }
  });

  test("every shipped prefix is a path, not a pattern", () => {
    for (const prefix of Object.keys(DEFAULT_LIMIT_TABLE.routes)) {
      expect(prefix.startsWith("/")).toBe(true);
      expect(prefix).not.toContain("*");
    }
  });

  test("no two prefixes are the same string", () => {
    const prefixes = Object.keys(DEFAULT_LIMIT_TABLE.routes);

    expect(new Set(prefixes).size).toBe(prefixes.length);
  });
});

describe("resolveLimit — one assertion per shipped entry", () => {
  const table = DEFAULT_LIMIT_TABLE;

  test("/auth/login is the strictest thing guard serves", () => {
    const limit = resolveLimit(table, "/auth/login");

    expect(limit.policy).toBe("guard-auth-login");
    expect(limit.limit).toBe(10);
    expect(limit.windowMs).toBe(60_000);
  });

  test("/auth/register is strict in its own right, not the login budget", () => {
    const limit = resolveLimit(table, "/auth/register");

    expect(limit.policy).toBe("guard-auth-register");
    expect(limit.limit).toBe(5);
  });

  test("brute-forcing a login does not spend the registration allowance", () => {
    // Same prefix family, different policy — so a separate bucket. A shared
    // one would let a caller who has exhausted registration also lock out
    // every legitimate sign-up from that address.
    expect(resolveLimit(table, "/auth/login").policy).not.toBe(resolveLimit(table, "/auth/register").policy);
  });

  test("/auth/logout has its own bucket", () => {
    expect(resolveLimit(table, "/auth/logout").policy).toBe("guard-auth-logout");
  });

  test("any other /auth route falls back to the auth-adjacent default", () => {
    const limit = resolveLimit(table, "/auth/me");

    expect(limit.policy).toBe("guard-auth");
  });

  test("/v1 uses the general API allowance", () => {
    const limit = resolveLimit(table, "/v1/me");

    expect(limit.policy).toBe("guard-api");
    expect(limit.limit).toBe(600);
    expect(limit.windowMs).toBe(60_000);
  });

  test("/v1/api-keys is its own, tighter surface", () => {
    const limit = resolveLimit(table, "/v1/api-keys");

    expect(limit.policy).toBe("guard-api-keys");
  });

  test("anything unrecognised falls back to the default", () => {
    expect(resolveLimit(table, "/").policy).toBe(DEFAULT_LIMIT_TABLE.default.policy);
    expect(resolveLimit(table, "/v2/anything").policy).toBe(DEFAULT_LIMIT_TABLE.default.policy);
  });
});

describe("resolveLimit — the matching rule", () => {
  const table: LimitTable = {
    default: { limit: 100, windowMs: 1000, policy: "default" },
    routes: {
      "/": { limit: 1, windowMs: 1000, policy: "root" },
      "/v1/": { limit: 2, windowMs: 1000, policy: "api" },
      "/v1/deep/": { limit: 3, windowMs: 1000, policy: "deep" },
    },
  };

  test("the longest matching prefix wins", () => {
    expect(resolveLimit(table, "/v1/deep/thing").policy).toBe("deep");
    expect(resolveLimit(table, "/v1/thing").policy).toBe("api");
    expect(resolveLimit(table, "/other").policy).toBe("default");
  });

  test("a prefix must end at a path segment boundary", () => {
    // `/v1/` must not claim `/v1alpha/`. Prefixes are read as path segments so
    // a new top-level route cannot inherit an allowance by name alone.
    expect(resolveLimit(table, "/v1alpha/thing").policy).toBe("default");
  });

  test("the root entry matches everything that nothing else claimed", () => {
    expect(resolveLimit(table, "/anything/at/all").policy).toBe("root");
  });

  test("the choice does not depend on the order the entries were written in", () => {
    const reversed: LimitTable = { default: table.default, routes: { "/v1/deep/": table.routes["/v1/deep/"]!, "/v1/": table.routes["/v1/"]!, "/": table.routes["/"]! } };

    expect(resolveLimit(reversed, "/v1/deep/thing").policy).toBe("deep");
  });

  test("a query string does not change which entry applies", () => {
    expect(resolveLimit(table, "/v1/thing?limit=1000").policy).toBe("api");
  });

  test("an empty table is the default, and does not throw", () => {
    expect(resolveLimit({ default: { limit: 1, windowMs: 1, policy: "only" } }, "/anything").policy).toBe("only");
  });
});
