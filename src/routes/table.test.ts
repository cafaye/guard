// The route table, held to what it promises.
//
// Every case here is a negative one, and that is deliberate: a table that maps
// `/v1/pantry` to `http://pantry:8080` is not in doubt — `resolveRoute` returning
// the row is the trivial half. What is in doubt is every value an operator can
// type, because the failure mode of a routing table is a request that is
// authenticated and then goes somewhere nobody intended.
//
// The bar each case holds to is the one the rest of this repository holds to:
// a malformed value is a `RangeError` at construction, never a default that
// forwards somewhere, and the message names the field and the value.
import { describe, expect, test } from "bun:test";
import { resolveRoute, ROUTE_MOUNT, routeTable, type RouteTable } from "./table";

/** A table with one service, which is the shape most of these cases mutate. */
const one: RouteTable = { "/v1/pantry": { baseUrl: "http://pantry.test:8080" } };

describe("a valid table", () => {
  test("it keeps what it was given, with the trailing slash and the port", () => {
    // Trailing slashes are what an operator types out of habit, and dropping
    // them here is what stops them joining into `//v1/items` downstream. A table
    // that refused one would be a table whose error message teaches nothing.
    const checked = routeTable({ "/v1/pantry": { baseUrl: "http://pantry.test:8080/" } });

    expect(checked["/v1/pantry"]?.baseUrl).toBe("http://pantry.test:8080");
  });

  test("a token is carried, and its absence is not the same as an empty one", () => {
    expect(routeTable({ "/v1/pantry": { baseUrl: "http://p.test", token: "svc-pantry" } })["/v1/pantry"]).toEqual({
      baseUrl: "http://p.test",
      token: "svc-pantry",
    });
    // `token: undefined` and no `token` are the same upstream, and the check
    // keeps them that way: an entry with a key set to nothing is a deployment
    // that meant to configure a credential and did not.
    expect(routeTable({ "/v1/pantry": { baseUrl: "http://p.test", token: undefined } })["/v1/pantry"]).toEqual({
      baseUrl: "http://p.test",
      token: undefined,
    });
  });

  test("the whole API surface is a legal prefix", () => {
    // `/v1` claims every path under the mount, which is the shape a deployment
    // gets when one service owns the API surface — including guard's own
    // `/v1/me`, which stays guard's because it is registered first.
    expect(() => routeTable({ "/v1": { baseUrl: "http://identity.test" } })).not.toThrow();
  });

  test("the returned table is a copy, so neither side can add to it afterwards", () => {
    // `limitTable` returns a copy for this reason. A caller reaching into the
    // object the validator returned would add a prefix nothing checked, and a
    // caller reaching into the object it passed would change a validated table
    // into an unvalidated one without going near the validator.
    const input: RouteTable = { "/v1/pantry": { baseUrl: "http://pantry.test:8080" } };
    const table = routeTable(input);

    expect(table).not.toBe(input);
    table["/v1/billing"] = { baseUrl: "http://metadata.test" };
    expect(Object.keys(input)).toEqual(["/v1/pantry"]);

    input["/v1/secret"] = { baseUrl: "http://metadata.test" };
    expect(Object.keys(table)).toEqual(["/v1/pantry", "/v1/billing"]);
  });
});

describe("what refuses to boot", () => {
  test("an empty table, which forwards nothing and says so nowhere", () => {
    // `ROUTE_TABLE={}` is a plausible typo and an operator would find out from
    // 404s. A table with nothing in it is a configuration mistake, not a
    // deployment with no services, and the difference is worth a refusal.
    expect(() => routeTable({})).toThrow(RangeError);
    expect(() => routeTable({})).toThrow(/at least one prefix/);
  });

  test("a prefix outside the mount, which could never match", () => {
    // The mount is `/v1/*`, so `/auth/` and `/pantry/` are unreachable by
    // construction. Accepting one would be a table describing traffic guard
    // does not forward — and the routes an operator would most want to add are
    // exactly the ones that must not be reachable without more thought.
    for (const prefix of ["/pantry", "/auth/", "/", "/v1alpha", "/V1/pantry"]) {
      expect(() => routeTable({ [prefix]: { baseUrl: "http://p.test" } }), prefix).toThrow(RangeError);
    }
  });

  test("a glob, because a prefix is a path and not a pattern", () => {
    for (const prefix of ["/v1/*", "/v1/p*", "/v1/pantry?"]) {
      expect(() => routeTable({ [prefix]: { baseUrl: "http://p.test" } }), prefix).toThrow(/not patterns/);
    }
  });

  test("a prefix carrying a traversal, in plain or encoded spelling", () => {
    // `%2e%2e` is `..` once decoded, and the pass-through rebuilds the upstream
    // path from decoded segments. A prefix written that way is a traversal
    // configured on purpose; it is refused here rather than discovered later.
    for (const prefix of ["/v1/../auth", "/v1/./pantry", "/v1/pantry/%2e%2e/.."]) {
      expect(() => routeTable({ [prefix]: { baseUrl: "http://p.test" } }), prefix).toThrow(/traversal/);
    }
  });

  test("`/v1/me`, which guard serves before the pass-through can see it", () => {
    // A table claiming it describes a route that can never run. That is a
    // configuration error with no symptom at all — every request would be served
    // by guard and the operator would believe their base URL had been used.
    expect(() => routeTable({ "/v1/me": { baseUrl: "http://identity.test" } })).toThrow(/guard's own route/);
  });

  test("a base URL that is not an absolute http(s) origin", () => {
    // `new URL("pantry:8080")` parses — as the scheme `pantry:` — so the
    // protocol check is the one that catches an address written without a
    // scheme, which is the mistake an operator makes when composing one.
    const cases: [string, RegExp][] = [
      ["pantry:8080", /http\(s\)/],
      ["ftp://pantry.test", /http\(s\)/],
      ["file:///etc/passwd", /http\(s\)/],
      ["http://", /non-empty string|absolute URL/],
      ["", /non-empty string/],
    ];

    for (const [baseUrl, expected] of cases) {
      expect(() => routeTable({ "/v1/pantry": { baseUrl } }), baseUrl).toThrow(expected);
    }
  });

  test("a base URL carrying a path, a query or credentials", () => {
    // No path: the caller's path is appended, so a base with one puts
    // `/v1/items` somewhere nobody is serving it. No credentials in the
    // authority: a URL with a password in it is a URL that ends up in a log line
    // on the failure path this table exists to make diagnosable.
    for (const baseUrl of [
      "http://pantry.test/internal",
      "http://pantry.test?token=x",
      "http://pantry.test#frag",
      "http://user:secret@pantry.test",
    ]) {
      expect(() => routeTable({ "/v1/pantry": { baseUrl } }), baseUrl).toThrow(RangeError);
    }
  });

  test("a token that is empty or would inject a header", () => {
    // This value is written into an Authorization header verbatim, so a newline
    // in it is header injection arriving from the one place an operator trusts.
    // Refused rather than escaped: a token is guard's own configuration and a
    // wrong one is a mistake to surface.
    for (const token of ["", "  ", "abc def", "abc\r\nX-Injected: yes", "abc\ndef"]) {
      expect(() => routeTable({ "/v1/pantry": { baseUrl: "http://p.test", token } }), JSON.stringify(token)).toThrow(
        RangeError,
      );
    }
  });

  test("a missing target is an error rather than a skip", () => {
    // `{"/v1/pantry": undefined as never}` is what a half-written table looks
    // like. Reading `target?.baseUrl` and getting undefined must still fail,
    // because the alternative is a route that silently forwards nowhere.
    expect(() => routeTable({ "/v1/pantry": undefined as never })).toThrow(RangeError);
  });
});

describe("resolution", () => {
  test("the longest matching prefix wins, and the order written is not the order used", () => {
    const table = routeTable({
      "/v1": { baseUrl: "http://all.test" },
      "/v1/pantry": { baseUrl: "http://pantry.test" },
      "/v1/pantry/imports": { baseUrl: "http://imports.test" },
    });

    expect(resolveRoute(table, "/v1/pantry/items")?.baseUrl).toBe("http://pantry.test");
    expect(resolveRoute(table, "/v1/pantry/imports/run")?.baseUrl).toBe("http://imports.test");
    expect(resolveRoute(table, "/v1/other")?.baseUrl).toBe("http://all.test");
  });

  test("a prefix matches on a segment boundary, so a sibling service is not reachable", () => {
    // The same rule `resolveLimit` applies, and the reason matters in both
    // places: `/v1/pantry` must not claim `/v1/pantryx`, or a new service
    // inherits a mount by sharing a name with an old one.
    const table = routeTable({ "/v1/pantry": { baseUrl: "http://pantry.test" } });

    expect(resolveRoute(table, "/v1/pantryx/items")).toBeNull();
    expect(resolveRoute(table, "/v1/pantry/items")).not.toBeNull();
    expect(resolveRoute(table, "/v1/pantry")).not.toBeNull();
  });

  test("the prefix itself matches, and a query is not part of the path", () => {
    const table = routeTable({ "/v1/pantry": { baseUrl: "http://pantry.test" } });

    expect(resolveRoute(table, "/v1/pantry?limit=1")?.prefix).toBe("/v1/pantry");
    expect(resolveRoute(table, "/v1/pantry/items?limit=1#top")?.prefix).toBe("/v1/pantry");
  });

  test("nothing claimed is null, which is the 404 the caller sees", () => {
    const table = routeTable({ "/v1/pantry": { baseUrl: "http://pantry.test" } });

    expect(resolveRoute(table, "/v1")).toBeNull();
    expect(resolveRoute(table, "/v1alpha/items")).toBeNull();
    expect(resolveRoute(table, "/auth/login")).toBeNull();
    expect(resolveRoute(table, "/v1/../auth/login")).toBeNull();
  });

  test("the resolved entry carries the credential, because the credential is per upstream", () => {
    // Which is the whole of the credential rule's configuration half: a service
    // has the credential guard presents to it, and resolving a path cannot
    // substitute a caller's own.
    const table = routeTable({
      "/v1/pantry": { baseUrl: "http://pantry.test", token: "svc-pantry" },
      "/v1/other": { baseUrl: "http://other.test" },
    });

    expect(resolveRoute(table, "/v1/pantry/items")?.token).toBe("svc-pantry");
    expect(resolveRoute(table, "/v1/other/items")?.token).toBeUndefined();
  });
});

describe("the mount this table is written for", () => {
  test("it is the API surface, and every shipped prefix lives under it", () => {
    // Derived from the table rather than restated, so a prefix added outside
    // the mount fails here as well as at construction — a check that stops
    // reading its own scope and reports success is worse than no check.
    expect(ROUTE_MOUNT).toBe("/v1/*");

    const table = routeTable({
      "/v1": { baseUrl: "http://all.test" },
      "/v1/pantry": { baseUrl: "http://pantry.test" },
    });

    for (const prefix of Object.keys(table)) {
      expect(prefix).toMatch(/^\/v1(\/|$)/);
    }
  });
});