// `openapi/v1.yaml` and the routes `createApp` registers have to describe the
// same gateway, and this is the test that holds them to it.
//
// PLAN.md §4b owes a doc-vs-router drift check before any SDK is generated from
// these documents, and this is it for guard. A path in `openapi/v1.yaml` becomes
// a method on a generated client, and a route the document does not mention is a
// method it does not have. Both directions are failures here.
//
// ## How it can fail, and how it cannot
//
// It reads both sides — the document, and Hono's own `app.routes` — and compares
// the **method+path pairs**, never a count. A count comparison is the shape that
// misses the change that matters: a rename leaves the count alone and a pure
// addition breaks it, which is exactly backwards.
//
// It cannot pass by reading nothing. `openapiPaths.ts` raises on every way it
// could under-read, and the two tests below assert that each side produced
// operations at all, because two readers that both find nothing agree.
//
// The route set is the **union over configurations**, and that is why the app
// below is built with every option switched on. `createApp` mounts the API-key
// gate, the `/v1/*` token gate, `/v1/me` and the whole `/auth` surface only when
// the matching option is present, so an app built with no options serves two
// routes and every other one would read as undocumented. A route that exists in
// *some* deployment is part of the surface this document has to describe; a
// check that could only see the sparsest configuration would be a check on a
// gateway nobody runs.
//
// ## What is not in the document, and why that is a decision
//
// `app.use(…)` mounts, and nothing else. `/v1/*` is the prefix the bearer-token
// gate and — when a route table is configured — the pass-through to the services
// behind guard are mounted on; it has no method, no response and no body of its
// own, so OpenAPI has nothing to describe it as. Hono records every middleware
// mount with the method `"ALL"`, which is what separates a mount from a route
// without a list of paths: `ALL /v1/*` and `GET /v1/me` are different *kinds* of
// thing, not one thing at two depths.
//
// So the exclusion is an **exact method+path pair**, never a prefix. A
// `startsWith("/v1/")` exclusion would cover every route the API surface gains
// from here on, and this packet exists to make exactly that class of quiet
// omission impossible. The test asserts that the exclusions name mounts and
// nothing else, and that each still names a mount the app registers — a rename
// cannot hide behind an exclusion that has gone stale.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createApp, PROBE_PATHS } from "../src/index";
import { memoryApiKeyStore } from "../src/middleware/apiKey";
import { RATE_LIMIT_HEADERS } from "../src/middleware/rateLimit";
import {
  describeDrift,
  diff,
  documentHeader,
  documentOperations,
  infoVersion,
  MOUNT_METHOD,
  normaliseOperation,
  openapiVersion,
  responseStatuses,
  routerSurface,
} from "./openapiPaths";

const DOCUMENT_PATH = "openapi/v1.yaml";

/** Every `app.use(…)` mount, by the normalised pair the check keys on. */
const EXCLUSIONS = new Map<string, string>([
  [
    normaliseOperation(MOUNT_METHOD, "/v1/*"),
    "the `/v1/*` prefix itself: the bearer-token gate is mounted on it, and the pass-through to the " +
      "services behind guard is mounted on it whenever a route table is configured. Neither is an " +
      "operation — each has no method and no response of its own, so there is nothing to document — and " +
      "a routed subtree is not describable as operations anyway: the paths under it belong to the service, " +
      "and which ones exist is decided by configuration rather than by this file. Excluded as this exact " +
      "method+path pair and NOT as a `/v1/` prefix, so a route added under `/v1/` next year is still " +
      "required to be in the document.",
  ],
  [
    normaliseOperation(MOUNT_METHOD, "/*"),
    "the whole-app mounts: the API-key gate and the rate limiter, both on `*`. Neither is an " +
      "operation, and each is a different gate, so they collapse onto one key here. Excluded " +
      "as this exact method+path pair; a route at the root is a `GET` or a `POST` and is not " +
      "covered by it.",
  ],
]);

/**
 * The app, built with every option on.
 *
 * Nothing is fetched and no socket is opened: `createApp` is importable without
 * serving, which is the whole reason the tests import the factory rather than the
 * process. `rateLimit: {}` is a real limiter over the in-memory store, `bff`
 * points at an identity that is never called because no request is made, and
 * `routes` is a real route table — which is the reason it is here. The route set
 * is the union over configurations, so an app built without a table would not
 * have the pass-through mounted, and a mount that exists in some deployments
 * would be invisible to this check.
 */
const app = createApp({
  jwt: { issuer: "https://identity.localhost", audience: "guard" },
  bff: { identityUrl: "http://identity.invalid:8080" },
  apiKeys: { keys: memoryApiKeyStore() },
  rateLimit: {},
  routes: { "/v1/pantry": { baseUrl: "http://pantry.invalid:8080", token: "not-a-real-token" } },
});

const surface = routerSurface(app.routes);

const document = readFileSync(fileURLToPath(new URL(`../${DOCUMENT_PATH}`, import.meta.url)), "utf8");
const documented = documentOperations(document, DOCUMENT_PATH);
const drift = diff(documented, surface.operations, EXCLUSIONS);

describe("the document and the router", () => {
  test("the document was read, and it describes something", () => {
    // Without this, the test below would compare an empty set against an empty set
    // and go green having checked nothing. The reader raises on most ways of
    // under-reading; this catches the rest.
    expect(documented.size).toBeGreaterThan(0);
  });

  test("the router was read, and it serves something", () => {
    expect(surface.operations.size).toBeGreaterThan(0);
  });

  test("every operation the document describes is a route the router serves", () => {
    // The dangerous direction, and the one that 404s a customer: an endpoint in
    // the menu that answers 404 is a product configured against a route that does
    // not exist, and they find out at their outage.
    expect(drift.documentedNotServed).toEqual([]);
  });

  test("every route the router serves is an operation the document describes", () => {
    // The other direction, and the one that was worth a packet: a route nobody
    // documented is a route the next generated client will not have.
    expect(drift.unexplained).toEqual([]);
  });
});

describe("the document is a document core's conventions accept", () => {
  test("it declares OpenAPI 3.1.0, which is the version the fleet publishes", () => {
    expect(openapiVersion(document, DOCUMENT_PATH)).toBe("3.1.0");
  });

  test("it declares `info.version`, and this is a new document so it starts at 1.0.0", () => {
    // core's conventions require the field, and it is the document's own semantic
    // version rather than the `/v1` prefix — the two answer different questions.
    expect(infoVersion(document, DOCUMENT_PATH)).toBe("1.0.0");
  });

  test("the media types it names are the two guard actually emits", async () => {
    // `application/problem+json` is the error envelope and `application/json` is
    // everything else — including the two responses (`404` and `500`) that are
    // still the v0 `{ error, message }` shape and are recorded as a conflict in
    // the document's header. A third media type here would be a media type no
    // response carries.
    const named = new Set([...document.matchAll(/^\s*application\/([a-z+]+):\s*$/gm)].map((m) => `application/${m[1]}`));

    expect([...named].sort()).toEqual(["application/json", "application/problem+json"]);

    // And the one an unregistered path really gets, read from the app rather than
    // from this list, so the assertion is against the program and not a comment.
    const notFound = await createApp().request("/no-such-route");

    expect(notFound.status).toBe(404);
    expect(notFound.headers.get("content-type")).toContain("application/json");
  });
});

describe("the error responses, which are the interesting part", () => {
  const statuses = responseStatuses(document, DOCUMENT_PATH);

  test("the problem envelope is one component, referenced rather than restated", () => {
    // A document that only describes the happy path is the usual way an OpenAPI
    // file becomes a lie, and guard's whole job is refusing requests. So the shape
    // is declared once and every error response points at it.
    expect(document).toContain("application/problem+json");
    expect(document).toMatch(/^ {4}Problem:$/m);
    // `Problem` is the schema every `application/problem+json` body refers to.
    const bodies = [...document.matchAll(/application\/problem\+json:\n(?:\s*.*\n)*?\s*\$ref: '#\/components\/schemas\/Problem'/g)];
    expect(bodies.length).toBeGreaterThan(0);
  });

  test("every operation the limiter counts declares the 429, and the probes do not", () => {
    // The exemption is `PROBE_PATHS` — the program's own set — so this is a claim
    // about which routes the limiter spares rather than a list of two paths
    // somebody typed. Everything else in the document can answer 429, because the
    // limiter is mounted on `*` and refuses every other path.
    const without = [...documented.keys()].filter((key) => !(statuses.get(key) ?? []).includes("429"));
    const probes = [...documented.keys()].filter((key) => PROBE_PATHS.has(surface.operations.get(key)?.path ?? ""));

    expect(without.sort()).toEqual(probes.sort());
    // Not vacuous: a document in which nothing declared a 429 would satisfy the
    // equality above with an empty left-hand side.
    expect(probes).toHaveLength(2);
  });

  test("every operation the document describes declares a 500, and that one is not a problem document", () => {
    // `app.onError` is the one place every handler's failure lands, so every
    // operation can answer it. It is the other half of the two-shapes conflict:
    // the envelope's `trace_id` has to match an `X-Trace-Id` on *every* response,
    // and that propagation middleware does not exist yet.
    //
    // The first assertion is the one that makes the loop mean anything: a reader
    // that found no responses would make every iteration below vacuous.
    expect([...statuses.keys()].sort()).toEqual([...documented.keys()].sort());
    for (const [key, declared] of statuses) {
      expect(declared, `${key} declares no 500`).toContain("500");
    }
  });

  test("the document names every rate-limit field the limiter announces", () => {
    // Read from `RATE_LIMIT_HEADERS`, which `rateLimit.test.ts` holds to what
    // `announce` actually sets — so a header added to the middleware without
    // being added to the document fails here rather than reaching a client
    // undocumented.
    for (const name of [...RATE_LIMIT_HEADERS, "Retry-After"]) {
      expect(document, `${DOCUMENT_PATH} never names ${name}`).toContain(name);
    }
  });
});

describe("the mount exclusions", () => {
  test("every entry the app registered is one the reader reported, in order", () => {
    // Element for element against Hono's own array, which is the thing this whole
    // packet is about. A reader that filtered, reordered or retyped an entry would
    // be agreeing with a smaller version of the truth and nothing below could tell.
    expect(surface.entries).toEqual(
      app.routes.map((route) => ({
        method: route.method.toUpperCase(),
        path: route.path,
        kind: route.method.toUpperCase() === MOUNT_METHOD ? "mount" : "operation",
      })),
    );
  });

  test("the mounts are the two the header names, and nothing else", () => {
    // Keyed by method *and* path, so a carve-out cannot cover a second method on
    // the same path, and the set is compared rather than a count: an addition here
    // is a change somebody reads rather than a diff line that scrolls past.
    expect([...surface.mounts.keys()].sort()).toEqual([...EXCLUSIONS.keys()].sort());
  });

  test("a declared omission still names a mount the app registers", () => {
    // The stale-exclusion guard. If `/v1/*` were unmounted, the exclusion would
    // still be in the list while matching nothing — and a carve-out that matches
    // nothing is a hole waiting for the next route to fall into it.
    for (const key of EXCLUSIONS.keys()) {
      expect(surface.mounts.has(key), `the exclusion for ${key} names a mount the app does not register`).toBe(true);
    }
  });
  test("the exclusions cover no operation, so they cannot swallow a future route", () => {
    // The failure this packet exists to prevent, stated as a test rather than as a
    // intention. Every exclusion is a mount, and no served operation is: a route
    // added under `/v1/` next year is a `GET` or a `POST` and none of these keys
    // can match it. `MOUNT_METHOD` is Hono's own spelling, read rather than
    // typed, so this is a claim about how `app.routes` records a mount.
    for (const [key] of EXCLUSIONS) expect(key.startsWith(`${MOUNT_METHOD} `)).toBe(true);
    for (const key of surface.operations.keys()) expect(EXCLUSIONS.has(key)).toBe(false);
  });

  test("`GET /v1/me` is documented rather than excluded, which is the live proof", () => {
    // The concrete version of the test above: the one route under the excluded
    // prefix is in the document, is served, and is not covered by a carve-out.
    expect(documented.has("GET /v1/me")).toBe(true);
    expect(surface.operations.has("GET /v1/me")).toBe(true);
    expect(EXCLUSIONS.has("GET /v1/me")).toBe(false);
  });

  test("the document's header names every mount the check excludes", () => {
    // The header is the only thing a reader of the document has to go on: a
    // document that silently omits a route is worse than one that says what it
    // covers. So a mount the check tolerates has to be a mount the document
    // admits, in words, above the `openapi:` key. Keyed by the same normalised
    // pair the exclusion uses, so the two cannot name different things.
    const header = documentHeader(document);

    for (const key of EXCLUSIONS.keys()) {
      expect(header, `${DOCUMENT_PATH} leaves ${key} out, and its header does not say so`).toContain(key);
    }
  });
});

describe("when it fails, the message says what to do", () => {
  test("the drift message names both sides, with the two fixes each", () => {
    const message = describeDrift(drift);

    // Nothing to say while the two agree, which is itself worth knowing: a green
    // check that produces a failure message nobody has read is a claim.
    expect(message).toBe("");
    expect(describeDrift({ ...drift, unexplained: [surface.operations.get("GET /v1/me")!] })).toContain(
      "document it in `openapi/v1.yaml`",
    );
  });
});
