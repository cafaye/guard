// Reads guard's OpenAPI document and the routes `createApp` actually registers,
// and says where they disagree. The check built on this is
// `openapiDocument.test.ts`; this module is the part of it that has to be right
// for that check to mean anything.
//
// It lives in guard's own `test/` rather than in a shared helper, so the next
// service that publishes a document copies one file and reads it.
//
// ## Both sets are read, neither is written down
//
// The document's operations come from `openapi/v1.yaml` and the router's from
// Hono's own `app.routes` — a real array of `{ basePath, path, method }` that the
// program fills in as it registers. Neither side is a list this repository
// maintains, because a list written out in a test is a check that can only fail
// for a name somebody remembered to type.
//
// ## Every reader refuses rather than under-reading
//
// A reader that comes back with an empty set agrees with another reader that
// comes back with an empty set. So every way this module could return less than
// it should — no `paths:` key, an empty block, a path item with no operations, a
// key that is neither a path nor a field of the Path Item Object, a missing
// `info.version`, an app that registers nothing — raises, with the file and line
// in the message. A loud reader is worth more than a green check over nothing.
//
// ## Why this is not a YAML parser
//
// guard's dependencies are `hono`, `jose` and the runtime (`AGENTS.md`: no
// dependency without a cause stated in review), and a YAML parser added only so
// a test can read a file is a dependency with no cause. So this reads the part
// of the document that describes routes — the `paths:` block and the keys under
// it — by indentation, and understands exactly that:
//
//   * `paths:` at column 0, path items one level in, operations one level below
//     that, and anything deeper is an operation's body and is not read. Both
//     levels are **derived from the document**, not assumed to be two and four,
//     so four-space YAML is read correctly rather than read as empty.
//   * A direct child of `paths:` is a path if it starts with `/`; otherwise it
//     has to be one of the fields OpenAPI 3.1 allows directly under a path —
//     `summary`, `description`, `servers`, `parameters`, `$ref`, `x-…` — and
//     anything else is an error rather than a guess.
//   * A key under a path is an operation if it is one of the eight HTTP method
//     names or a field of the Path Item Object, and nothing else. `getaway:` is
//     not a `GET`.
//
// Anything outside that subset raises. A service that needs a real parser should
// add one and delete this; the check itself does not change.

/** One route the router serves, or one operation the document describes. */
export type Operation = {
  /** Upper case: `GET`, `POST`, … */
  method: string;
  /** The path as written, before normalisation. */
  path: string;
  /** `METHOD /path`, for a failure message. */
  label: string;
  /**
   * The line the path starts on. Documents only: `app.routes` is an array, not a
   * file, so a router operation has no line and `undefined` is the honest answer
   * rather than a number that points nowhere.
   */
  line?: number;
};

/**
 * One `app.use(…)` mount. It is not an operation and OpenAPI has nothing to
 * describe it as one: it has no method, it has no response of its own, and in
 * guard's case (`/v1/*`) it is a pass-through in front of a surface no single
 * service owns. `app.routes` records it with the method `"ALL"`, and that is
 * the whole distinction.
 */
export type Mount = { method: string; path: string; label: string };

export type RouterEntry = { method: string; path: string; kind: "operation" | "mount" };

export type RouterSurface = {
  /** Keyed `METHOD /path`, deduplicated. */
  operations: Map<string, Operation>;
  /** Keyed `METHOD /path`, deduplicated. */
  mounts: Map<string, Mount>;
  /**
   * Every entry `app.routes` reported, in registration order, tagged.
   *
   * Kept so the check can compare the reader's output against the program's own
   * array element for element. A reader that filtered, reordered or retyped an
   * entry would otherwise be agreeing with a smaller version of the truth, and
   * nothing downstream could tell.
   */
  entries: RouterEntry[];
};

/** The eight HTTP method names OpenAPI 3.1 names as operations. */
const METHODS = ["get", "head", "post", "put", "patch", "delete", "options", "trace"] as const;

/** The fields OpenAPI 3.1 allows directly under a path key. Path Item Object. */
const PATH_ITEM_FIELDS = ["summary", "description", "servers", "parameters", "$ref"] as const;

/**
 * Hono registers middleware with the method `ALL` and a route with the route's
 * own method. This is the *only* thing that tells the two apart, and it is why
 * the exclusion below can be an exact method+path rather than a path prefix: a
 * mounted `ALL /v1/*` and a served `GET /v1/me` are different kinds of thing, not
 * one thing at two depths.
 */
export const MOUNT_METHOD = "ALL";

/** A line, its indentation and its 1-based number. */
type Line = { indent: number; text: string; number: number };

/** The normalised `{method, path}` an operation or mount is keyed by. */
export function normaliseOperation(method: string, path: string): string {
  return `${normaliseMethod(method)} ${normalisePath(path)}`;
}

export function normaliseMethod(method: string): string {
  return method.toUpperCase();
}

/**
 * The path with a path parameter's whole segment replaced by `{}` and any
 * trailing slash removed. Both rewrites are mechanical, and both are applied to
 * the document and the router alike — there is no "document rules" and "router
 * rules", because a normaliser that treats the two sides differently is one that
 * can hide a difference.
 *
 * A `*glob` segment is left alone. It matches an arbitrary tail of a path, which
 * is a different shape from a `{param}`'s single segment, and treating the two as
 * one is the kind of rewrite that hides a real difference.
 */
export function normalisePath(path: string): string {
  const rewritten = path
    .split("/")
    .map((segment) => (/^[:{]/.test(segment) ? "{}" : segment))
    .join("/");

  return rewritten.length > 1 ? rewritten.replace(/\/+$/, "") : rewritten;
}

/** Every operation the document describes, or a raised error. */
export function documentOperations(contents: string, name: string): Map<string, Operation> {
  const lines = significant(contents);
  const block = pathsBlock(lines, name);
  const [pathLevel, methodLevel] = levels(block, name);

  // Each group is one direct child of `paths:` plus everything indented under it,
  // because the level a key sits at is what makes it a path item.
  const operations = new Map<string, Operation>();

  for (const group of groups(block, pathLevel)) {
    const key = keyOf(group[0].text);

    if (!key.startsWith("/")) {
      if (pathItemField(key)) continue;
      throw new Error(
        `${name}:${group[0].number} — \`${key}\` is not a valid OpenAPI path. Every key directly ` +
          `under \`paths:\` is a path starting with \`/\`, or a field of the Path Item Object ` +
          `(${PATH_ITEM_FIELDS.join(", ")}, x-…). This reader refuses the document rather than ` +
          `guessing which was meant, because a misspelled sibling is a document that describes no ` +
          `route and an empty result would agree with a router that serves several.`,
      );
    }

    // One pass: every key at the operation level is either an operation or a field
    // of the Path Item Object, and anything else is refused before it can become a
    // route in the menu.
    const found: string[] = [];
    for (const line of group.filter((candidate) => candidate.indent === methodLevel)) {
      const key2 = keyOf(line.text);
      if (pathItemField(key2)) continue;
      if (!isMethod(key2)) {
        throw new Error(
          `${name}:${group[0].number} — \`${key2}\` is not an OpenAPI operation. A key directly ` +
            `under a path is one of ${METHODS.join(", ")}, or a field of the Path Item Object. ` +
            `Reading it as anything else would put a route in the menu that no client can call.`,
        );
      }
      found.push(key2);
    }

    if (found.length === 0) {
      throw new Error(
        `${name}:${group[0].number} — the path \`${key}\` has no operation under it. A path item ` +
          `with no operation is nothing a client can be generated from, and skipping it would leave ` +
          `this check agreeing with a document that says nothing about a route the router serves.`,
      );
    }

    for (const method of found) {
      const operationKey = normaliseOperation(method, key);
      const previous = operations.get(operationKey);
      if (previous !== undefined) {
        throw new Error(
          `${name}:${group[0].number} — two operations both read as ${operationKey}: \`${previous.label}\` and ` +
            `\`${method} ${key}\`. They normalise onto one route, so a check that could not see the ` +
            `collision would be blind to it.`,
        );
      }
      operations.set(operationKey, {
        method: normaliseMethod(method),
        path: key,
        label: `${normaliseMethod(method)} ${key}`,
        line: group[0].number,
      });
    }
  }

  return operations;
}

/**
 * The response statuses each operation declares, keyed like `documentOperations`.
 *
 * A second reading of the same subset, for a claim the first one cannot make: an
 * operation can be in the document and still be wrong, and "a `429` is missing
 * from every route the limiter counts" is not visible in a list of method+path
 * pairs. Statuses are read at exactly one level under `responses:`, so a media
 * type, a header name and an example name further down are not statuses.
 */
export function responseStatuses(contents: string, name: string): Map<string, string[]> {
  const lines = significant(contents);
  const block = pathsBlock(lines, name);
  const [pathLevel, methodLevel] = levels(block, name);
  const statuses = new Map<string, string[]>();

  for (const group of groups(block, pathLevel)) {
    const path = keyOf(group[0].text);
    if (!path.startsWith("/")) continue;

    // Scoped to this method's own lines, so a second method on the same path
    // reports its own responses rather than the first one's.
    const methodLines = group
      .map((line, index) => ({ line, index }))
      .filter(({ line }) => line.indent === methodLevel && isMethod(keyOf(line.text)));

    for (const { line, index } of methodLines) {
      const method = keyOf(line.text);
      const label = `${normaliseMethod(method)} ${path}`;
      const next = methodLines.find((candidate) => candidate.index > index)?.index ?? group.length;
      const body = group.slice(index + 1, next);
      const responses = body.find((candidate) => candidate.indent > methodLevel && keyOf(candidate.text) === "responses");
      if (responses === undefined) {
        throw new Error(
          `${name}:${group[0].number} — the operation \`${label}\` has no \`responses:\` block. An ` +
            `operation with no responses is nothing a client can be generated from, and reading it as ` +
            `one that answers nothing is the same shape as a check over an empty set.`,
        );
      }

      const start = body.indexOf(responses);
      const inside = body.slice(start + 1).filter((candidate) => candidate.indent > responses.indent);
      const first = inside.length === 0 ? -1 : Math.min(...inside.map((candidate) => candidate.indent));
      const found = inside
        .filter((candidate) => candidate.indent === first)
        .map((candidate) => keyOf(candidate.text))
        .filter((key) => /^\d{3}$/.test(key));

      if (found.length === 0) {
        throw new Error(
          `${name}:${responses.number} — \`${label}\` declares no responses: nothing at all is ` +
            `listed under its \`responses:\` key. An operation that can answer nothing and an ` +
            `operation whose responses were lost to a reformat are the same file, and only one of ` +
            `them is true.`,
        );
      }

      statuses.set(label, found);
    }
  }

  return statuses;
}

/** Everything above the `openapi:` key: the document's header, as written. */
export function documentHeader(contents: string): string {
  const lines = contents.split("\n");
  const index = lines.findIndex((line) => line.trimStart().startsWith("openapi:"));
  if (index < 0) return lines.join("\n");

  return `${lines.slice(0, index).join("\n")}\n`;
}

/** The `openapi:` version, or a raised error. */
export function openapiVersion(contents: string, name: string): string {
  const value = topLevelScalar(contents, name, "openapi");
  if (value === null) {
    throw new Error(`${name} declares no \`openapi:\` version. The document's dialect is the one thing a reader cannot assume.`);
  }
  return value;
}

/**
 * `info.version`, or a raised error.
 *
 * Required by core's conventions and by the brief: it is the document's own
 * semantic version, and without it a consumer cannot tell "nothing moved" from
 * "the whole document was regenerated".
 */
export function infoVersion(contents: string, name: string): string {
  const lines = significant(contents);
  const info = lines.find((line) => line.indent === 0 && line.text === "info:");
  if (info === undefined) throw new Error(`${name} has no top-level \`info:\` key, and so no info.version.`);

  const version = lines.find((line) => line.indent > 0 && keyOf(line.text) === "version");
  if (version === undefined) {
    throw new Error(
      `${name}:${info.number} — \`info:\` has no \`info.version\`. core's conventions ` +
        `require it, and a reader that reported null would agree with a document that forgot it.`,
    );
  }

  const value = valueOf(version.text);
  if (value === "") throw new Error(`${name}:${version.number} — \`info.version\` is present and empty.`);

  return value;
}

/** What the router serves: its operations and its middleware mounts. */
export function surfaceOf(routes: readonly { path: string; method: string }[], who: string): RouterSurface {
  if (routes.length === 0) {
    throw new Error(
      `${who} serves no routes at all. A router-reading check that finds nothing agrees with a ` +
        `document-reading check that finds no paths, and two empty sets always agree.`,
    );
  }

  const operations = new Map<string, Operation>();
  const mounts = new Map<string, Mount>();
  const entries: RouterEntry[] = [];

  for (const route of routes) {
    const method = normaliseMethod(route.method);
    const key = normaliseOperation(method, route.path);
    const mount = method === MOUNT_METHOD;

    // A method this reader does not know is raised on rather than filed. Filing it
    // as an operation would put a route in the document's comparison set that
    // nothing can serve, and filing it as a mount would hide it inside a carve-out.
    if (!mount && !isMethod(method)) {
      throw new Error(
        `${who} registers \`${method} ${route.path}\`, which is neither one of ${METHODS.join(", ")} nor ` +
          `the \`${MOUNT_METHOD}\` Hono records a middleware mount with. This reader will not guess which ` +
          `kind of thing that is: a misfiled entry is either a route no client can call or a mount ` +
          `hiding inside a carve-out.`,
      );
    }

    entries.push({ method, path: route.path, kind: mount ? "mount" : "operation" });

    if (mount) {
      mounts.set(key, { method, path: route.path, label: key });
    } else {
      // Hono registers one entry per handler in a chain, so
      // `app.post(path, gate, handler)` arrives twice for one route. Set rather
      // than throw: unlike a document, there is no ambiguity here to refuse — the
      // two entries are the same route reached through two handlers.
      operations.set(key, { method, path: route.path, label: key });
    }
  }

  return { operations, mounts, entries };
}

/** `surfaceOf`, naming `createApp` in the message when it is the thing that is empty. */
export function routerSurface(routes: readonly { path: string; method: string }[]): RouterSurface {
  return surfaceOf(routes, "the Hono app");
}

/**
 * Where the two sets disagree, in three parts.
 *
 *   * `documentedNotServed` — the document has it, the router does not. This is
 *     the direction that 404s a client.
 *   * `servedNotDocumented` — every operation the router serves that the
 *     document does not describe, whatever the reason.
 *   * `unexplained` — the ones no exclusion covers. This is what a check fails
 *     on; the difference between it and `servedNotDocumented` is a declared
 *     choice rather than an oversight, and the message prints the choice so it
 *     cannot be read as an accident.
 */
export type Drift = {
  documentedNotServed: Operation[];
  servedNotDocumented: Operation[];
  unexplained: Operation[];
  excluded: (Operation & { reason: string })[];
};

export function diff(
  document: Map<string, Operation>,
  router: Map<string, Operation>,
  exclusions: ReadonlyMap<string, string> = new Map(),
): Drift {
  const missing = [...router.keys()].filter((key) => !document.has(key));
  const explained = missing.filter((key) => exclusions.has(key));
  const unexplained = missing.filter((key) => !exclusions.has(key));

  return {
    documentedNotServed: [...document.keys()].filter((key) => !router.has(key)).map((key) => document.get(key)!),
    servedNotDocumented: missing.map((key) => router.get(key)!),
    unexplained: unexplained.map((key) => router.get(key)!),
    excluded: explained.map((key) => ({ ...router.get(key)!, reason: exclusions.get(key)! })),
  };
}

/** The message a failure prints, built to be actionable on its own. */
export function describeDrift(found: Drift): string {
  return [
    section(
      found.documentedNotServed,
      "the document describes",
      "the router does not serve",
      "An endpoint in the menu that answers 404 is a product configured against a route that does not exist, and they find out at their outage.",
      [
        "The route is real and shipping — add it to `src/index.ts`.",
        "The operation is not shipping — delete it from `openapi/v1.yaml`.",
      ],
    ),
    section(
      found.unexplained,
      "the router serves",
      "the document does not describe",
      "A route nobody documented is a route the next generated client will not have, so the surface grows and the contract does not.",
      [
        "The route is part of guard's public surface — document it in `openapi/v1.yaml`.",
        "The route is not meant to be public — say so in the document's header, and name it in this test's exclusion list, rather than leaving it to be found.",
      ],
    ),
    exclusionsNote(found.excluded),
  ]
    .filter((part) => part !== null && part !== "")
    .join("\n\n");
}

// --- reading a document ---------------------------------------------------

function significant(contents: string): Line[] {
  return contents
    .split("\n")
    .map((raw, index) => ({ raw, number: index + 1 }))
    .filter(({ raw }) => {
      const trimmed = raw.trimStart();
      return trimmed !== "" && !trimmed.startsWith("#");
    })
    .map(({ raw, number }) => ({
      indent: raw.length - raw.trimStart().length,
      text: raw.trim().replace(/\s+#.*$/, ""),
      number,
    }));
}

function pathsBlock(lines: Line[], name: string): Line[] {
  const index = lines.findIndex((line) => line.indent === 0 && line.text === "paths:");
  if (index < 0) {
    throw new Error(
      `${name} has no top-level \`paths:\` key. A reader that cannot find the document's paths finds ` +
        `none, and a check over none passes — so this is an error, not an empty result.`,
    );
  }

  // The block ends at the next top-level key. Filtering the rest of the file
  // instead would swallow `components:` — a key that is not a path, in a section
  // that is not `paths`, read as though it were one.
  const block: Line[] = [];
  for (const line of lines.slice(index + 1)) {
    if (line.indent === 0) break;
    block.push(line);
  }

  if (block.length === 0) {
    throw new Error(
      `${name} documents no operations: nothing is under its \`paths:\` key. Two readers that both ` +
        `find nothing agree, which is how a check over nothing goes green.`,
    );
  }

  return block;
}

/** The two levels are derived from the document, so four-space YAML reads correctly. */
function levels(block: Line[], name: string): [number, number] {
  const found = [...new Set(block.map((line) => line.indent))].sort((a, b) => a - b);
  if (found.length < 2 || found[0] === undefined || found[1] === undefined) {
    throw new Error(
      `${name} documents no operations: what is under \`paths:\` is one indentation level deep, so ` +
        `there is no operation level below the path items.`,
    );
  }

  return [found[0], found[1]];
}

function groups(block: Line[], pathLevel: number): [Line, ...Line[]][] {
  const out: [Line, ...Line[]][] = [];
  for (const line of block) {
    if (line.indent === pathLevel || out.length === 0) out.push([line]);
    else out[out.length - 1]?.push(line);
  }

  return out;
}

function topLevelScalar(contents: string, name: string, key: string): string | null {
  for (const line of significant(contents)) {
    if (line.indent !== 0 || keyOf(line.text) !== key) continue;
    const value = valueOf(line.text);

    return value === "" ? null : value;
  }

  return null;
}

/**
 * The key part of a `key:` or `key: value` line, and the value part of the
 * second. YAML keys in this subset are the text before a colon that is followed
 * by whitespace or by the end of the line, so a path that somehow contained a
 * colon inside a segment is not split mid-segment.
 *
 * Quotes are stripped, because a response status has to be quoted to stay a
 * string in YAML (`'200':`) and `'200'` is not the status a client reads.
 */
function keyOf(text: string): string {
  const key = /^([^:]*?):(\s|$)/.exec(text)?.[1]?.trim() ?? text;

  return /^(['"]).*\1$/.test(key) ? key.slice(1, -1) : key;
}

function valueOf(text: string): string {
  return text.replace(/^[^:]*?:/, "").trim();
}

function isMethod(key: string): boolean {
  return (METHODS as readonly string[]).includes(key);
}

function pathItemField(key: string): boolean {
  return (PATH_ITEM_FIELDS as readonly string[]).includes(key) || key.startsWith("x-");
}

// --- reporting -----------------------------------------------------------

function section(offenders: Operation[], subject: string, absence: string, why: string, fixes: string[]): string {
  if (offenders.length === 0) return "";

  return [
    `${subject} ${count(offenders)} ${absence}.`,
    `  ${why}`,
    "  Offending operations:",
    ...offenders.map((operation) => `    ${operation.label}`),
    "  To fix this, do one of the two things:",
    ...fixes.map((fix, index) => `    ${index + 1}. ${fix}`),
    "  This check is `test/openapiDocument.test.ts`; the reader is `test/openapiPaths.ts`.",
  ].join("\n");
}

function exclusionsNote(excluded: (Operation & { reason: string })[]): string {
  if (excluded.length === 0) return "";

  return [
    "Declared omissions — the router serves these and the document does not, on purpose:",
    ...excluded.map((operation) => `  ${operation.label} — ${operation.reason}`),
  ].join("\n");
}

function count(offenders: Operation[]): string {
  return `${offenders.length} operation${offenders.length === 1 ? "" : "s"}`;
}
