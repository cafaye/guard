// `test/openapiPaths.ts`, held to its own contract.
//
// The drift check in `openapiDocument.test.ts` is only as trustworthy as the two
// readers underneath it, and a reader's interesting behaviour is almost entirely
// what it does when the file is not what it expected. Every case below is a way
// the reader could come back with less than it should, and every one of them is a
// raised error rather than a smaller set — because a reader that finds nothing
// and a document that describes nothing always agree, and a check over nothing
// passes.
//
// The line between the two tests is the courier one: this file is about whether
// the readers understand their inputs, and the other is about whether the
// document and the router understand each other.
import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import type { Handler, MiddlewareHandler } from "hono";
import {
  documentHeader,
  documentOperations,
  infoVersion,
  normaliseOperation,
  normalisePath,
  openapiVersion,
  responseStatuses,
  routerSurface,
  surfaceOf,
} from "./openapiPaths";

/** A document with two paths, three operations and a path item field. */
const DOCUMENT = [
  "openapi: 3.1.0",
  "",
  "info:",
  "  title: cafaye guard",
  "  version: 1.0.0",
  "",
  "paths:",
  "  /healthz:",
  "    get:",
  "      operationId: liveness",
  "      responses:",
  "        '200':",
  "          description: ok",
  "    summary: Liveness",
  "  /auth/login:",
  "    post:",
  "      operationId: login",
  "      responses:",
  "        '200':",
  "          description: ok",
  "",
].join("\n");

describe("the document reader", () => {
  test("reads one operation per method under each path", () => {
    const operations = documentOperations(DOCUMENT, "openapi/v1.yaml");

    expect([...operations.keys()].sort()).toEqual(["GET /healthz", "POST /auth/login"]);
    // The line the *path* starts on, which is what a failure message needs: a
    // client reading `openapi/v1.yaml:8` looks for the path, not the method.
    expect(operations.get("GET /healthz")?.line).toBe(8);
  });

  test("a path-item field under a path is not an operation", () => {
    // `summary:` sits one level below a path item and belongs to the path, not to
    // a `SUMMARY` method. A reader that treated any key at that level as an
    // operation would report a route Hono never serves.
    expect(documentOperations(DOCUMENT, "v1.yaml").has("SUMMARY /healthz")).toBe(false);
  });

  test("a method key inside a request body is not an operation", () => {
    const withBody = DOCUMENT.replace(
      "      responses:",
      "      requestBody:\n        content:\n          application/json:\n            schema:\n              properties:\n                delete:\n                  type: string\n      responses:",
    );

    // A schema property called `delete` is a field, not a `DELETE`. Only a key at
    // the operation level counts, which is what makes depth part of the reading.
    expect(documentOperations(withBody, "v1.yaml").has("DELETE /healthz")).toBe(false);
  });

  test("four-space indentation is read as four-space indentation", () => {
    const wide = DOCUMENT.replace(/^ {2}/gm, "    ");
    const operations = documentOperations(wide, "v1.yaml");

    expect([...operations.keys()].sort()).toEqual(["GET /healthz", "POST /auth/login"]);
  });

  test("a path item with no operation under it is an error, not a skipped path", () => {
    const empty = ["openapi: 3.1.0", "", "paths:", "  /healthz:", "    summary: nothing here", ""].join("\n");

    // Skipping it would leave the check comparing a document that says nothing
    // about this route against a router that serves it, and agreeing with it.
    expect(() => documentOperations(empty, "v1.yaml")).toThrow(/no operation/);
  });
});

describe("the document reader refuses rather than under-reads", () => {
  test("a document with no top-level `paths:` key", () => {
    expect(() => documentOperations("openapi: 3.1.0\ninfo:\n  title: x\n", "v1.yaml")).toThrow(/no top-level `paths:`/);
  });

  test("a `paths:` with nothing under it", () => {
    expect(() => documentOperations("openapi: 3.1.0\n\npaths:\n", "v1.yaml")).toThrow(/no operations/);
  });

  test("a `paths:` whose children are one level deep", () => {
    const flat = ["paths:", "  /healthz:", ""].join("\n");

    expect(() => documentOperations(flat, "v1.yaml")).toThrow(/no operation level/);
  });

  test("a key under `paths:` that is neither a path nor a path-item field", () => {
    const typo = ["paths:", "  /healthz:", "    get:", "      responses:", "        '200':", "          description: ok", "  opertaions: {}", ""].join(
      "\n",
    );

    // A misspelled `paths` sibling is a document that describes no route, and an
    // empty result would read as a document that describes every route correctly.
    expect(() => documentOperations(typo, "v1.yaml")).toThrow(/not a valid OpenAPI path/);
  });

  test("a key under a path that is neither a method nor a path-item field", () => {
    const typo = ["paths:", "  /healthz:", "    getaway:", "      responses: {}", ""].join("\n");

    expect(() => documentOperations(typo, "v1.yaml")).toThrow(/not an OpenAPI operation/);
  });

  test("the file's own name is in the error, so a failure says where to look", () => {
    expect(() => documentOperations("openapi: 3.1.0\n", "openapi/v1.yaml")).toThrow(/openapi\/v1\.yaml/);
  });
});

describe("the response-status reader", () => {
  test("every status under `responses:` is read, quoted or not", () => {
    const withStatuses = [
      "paths:",
      "  /v1/me:",
      "    get:",
      "      operationId: me",
      "      responses:",
      "        '200':",
      "          description: ok",
      "        '401':",
      "          $ref: '#/components/responses/Unauthenticated'",
      "        429:",
      "          description: slow down",
      "",
    ].join("\n");

    // A `$ref`'d response is still a response the document declares, and a 429
    // written unquoted is still a 429. The reader is about which statuses an
    // operation can answer, not how the document spells them.
    expect(responseStatuses(withStatuses, "v1.yaml").get("GET /v1/me")).toEqual(["200", "401", "429"]);
  });

  test("an operation with no `responses:` block is an error rather than an empty list", () => {
    const bare = ["paths:", "  /healthz:", "    get:", "      operationId: liveness", ""].join("\n");

    // An empty status list would read as "this operation answers nothing", which
    // is the same shape as a check that compared two empty sets.
    expect(() => responseStatuses(bare, "v1.yaml")).toThrow(/no `responses:`/);
  });

  test("an operation that declares no status is an error", () => {
    const empty = ["paths:", "  /healthz:", "    get:", "      responses:", ""].join("\n");

    expect(() => responseStatuses(empty, "v1.yaml")).toThrow(/declares no responses/);
  });
});

describe("the document's own metadata", () => {
  test("the header is everything above the `openapi:` key", () => {
    const header = ["# a note", "# > DECISION NEEDED (guard-06): something", "openapi: 3.1.0", "info:", "  title: x"].join(
      "\n",
    );

    // The header is the only thing a reader of the document has to go on, so it
    // has to be the part above the document rather than the `info.description`
    // buried inside it.
    expect(documentHeader(header)).toBe("# a note\n# > DECISION NEEDED (guard-06): something\n");
  });

  test("the declared OpenAPI version and the document version are read", () => {
    expect(openapiVersion(DOCUMENT, "v1.yaml")).toBe("3.1.0");
    expect(infoVersion(DOCUMENT, "v1.yaml")).toBe("1.0.0");
  });

  test("a document with no `info.version` says so rather than reporting null", () => {
    const unversioned = DOCUMENT.replace("  version: 1.0.0\n", "");

    // core's conventions require `info.version`, and a null here would be a
    // reader that agrees with a document that forgot it.
    expect(() => infoVersion(unversioned, "v1.yaml")).toThrow(/info.version/);
  });
});

describe("path normalisation", () => {
  test("a path parameter reads the same whichever side spells it", () => {
    // A client substitutes a path parameter positionally, so `:id`, `{id}` and
    // `{id}.json` are one route with three spellings. Both sides go through the
    // same function — a normaliser that treated them differently is a normaliser
    // that can hide a difference.
    expect(normalisePath("/v1/users/:id")).toBe("/v1/users/{}");
    expect(normalisePath("/v1/users/{id}")).toBe("/v1/users/{}");
    expect(normalisePath("/v1/users/{id}.json")).toBe("/v1/users/{}");
  });

  test("a trailing slash is not a difference", () => {
    expect(normalisePath("/v1/me/")).toBe("/v1/me");
    expect(normalisePath("/")).toBe("/");
  });

  test("a `*` segment is left alone, because it is a different shape", () => {
    // `/v1/*` matches an arbitrary tail of a path and `{param}` matches one
    // segment. Rewriting a glob into a parameter would make the one thing this
    // repository mounts as middleware look like a route.
    expect(normalisePath("/v1/*")).toBe("/v1/*");
  });

  test("a method is normalised to upper case, and the key is method plus path", () => {
    expect(normaliseOperation("get", "/healthz")).toBe("GET /healthz");
    expect(normaliseOperation("ALL", "/v1/*")).toBe("ALL /v1/*");
  });
});

describe("the router reader", () => {
  /** A Hono app shaped like guard's, with one route and one middleware. */
  const app = new Hono();
  app.get("/healthz", (c) => c.text("ok"));
  app.use("/v1/*", async (_c, next) => next());

  test("a real route is an operation and a middleware mount is not", () => {
    const surface = routerSurface(app.routes);

    expect([...surface.operations.keys()]).toEqual(["GET /healthz"]);
    // The distinction is Hono's own: `app.get` registers a method, `app.use`
    // registers `"ALL"`. A glob path is not a route, and a method name is.
    expect([...surface.mounts.keys()]).toEqual(["ALL /v1/*"]);
  });

  test("every entry the app registered is reported, in order", () => {
    const surface = routerSurface(app.routes);

    // Element for element against the program's own array, which is the thing
    // this whole packet is about. A reader that filtered, reordered or retyped an
    // entry would be agreeing with a smaller version of the truth.
    expect(surface.entries).toEqual([
      { method: "GET", path: "/healthz", kind: "operation" },
      { method: "ALL", path: "/v1/*", kind: "mount" },
    ]);
  });

  test("a route mounted behind middleware is one operation, not two", () => {
    // `app.post(path, gate, handler)` registers one entry per handler in the
    // chain. Reading those as two routes would invent a method the router does
    // not serve, which is the same class of error as the other direction.
    const chained = new Hono();
    const gate: MiddlewareHandler = async (_c, next) => next();
    const handler: Handler = (c) => c.text("ok");
    chained.post("/auth/login", gate, handler);

    const surface = routerSurface(chained.routes);

    expect([...surface.operations.keys()]).toEqual(["POST /auth/login"]);
    expect(surface.entries).toHaveLength(2);
  });

  test("a method this reader does not know is raised on, not filed", () => {
    // Filing it as an operation would put a route in the comparison set nothing
    // can serve; filing it as a mount would hide it inside a carve-out. Both are
    // quieter than saying so, which is why this raises.
    expect(() => surfaceOf([{ method: "PROPFIND", path: "/v1/me" }], "a Hono app")).toThrow(
      /neither one of GET, HEAD, POST/,
    );
  });
});

describe("surfaceOf", () => {
  test("an app with no routes at all is an error, not an empty set", () => {
    // Two readers that both find nothing agree. This is what stops that.
    expect(() => surfaceOf(new Hono().routes, "guard")).toThrow(/serves no routes/);
  });
});
