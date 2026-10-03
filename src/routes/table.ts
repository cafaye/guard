// Which path prefix goes to which service, in configuration rather than in code.
//
// A gateway that authenticates a caller and then has nowhere to send them is a
// gateway that terminates auth for its own sake. This file is the half of
// forwarding that can be decided without any of forwarding: the table of
// prefixes and upstreams, validated at construction, plus the one question a
// request asks of it — "who owns this path?".
//
// ## Why a static table and not a registry
//
// The set of services in a deployment is small, known, and changes with a
// deploy rather than at runtime, so a table read from configuration is the
// honest shape *now* rather than a simplification. Discovery, health and
// dynamic registration are a later packet, and the table is deliberately the
// thing such a registry would *populate*: `RouteTable` is a plain object, so
// filling it from a registry is writing a different `runtimeOptions` and
// changing nothing in `createApp`, the middleware, or the matching rule below.
// That is the property that makes the swap a populate rather than a rewrite,
// and it is why there is no interface indirection here waiting for a consumer
// that does not exist yet.
//
// ## What is validated, and why each one is a startup error
//
// `REDIS_URL=redis//redis` refusing to boot is the precedent, and every rule
// below is the same argument about a value an operator typed:
//
//   * a prefix outside `/v1/` could never match, because the pass-through is
//     mounted on the API surface — a route that silently forwards nothing;
//   * a glob (`*`, `?`) is a second matching language, and the only question a
//     route asks is "everything under here";
//   * a base URL carrying a path would put the caller's path somewhere nobody
//     is serving it — the same rule `parseIdentityUrl` applies to identity;
//   * `/v1/me` is guard's own route, registered before the pass-through, so a
//     table claiming it describes a route that can never run;
//   * a token with a line break in it is header injection through configuration
//     rather than through a request, which is not a smaller problem.
import { assertNonEmptyString } from "../middleware/assert";

/** One upstream, and the credential guard attaches when it calls. */
export type RouteTarget = {
  /**
   * The service's base URL: http(s), no path, no query, no fragment and no
   * credentials in the authority.
   *
   * No path is the load-bearing half. The caller's remaining path is appended
   * to it, so a base carrying one would put `/v1/items` under a prefix the
   * operator typed out of habit and nobody serves.
   */
  baseUrl: string;
  /**
   * The credential guard presents to this service, as a bearer token.
   *
   * Optional, and its absence is meaningful: a service that authenticates
   * nothing (pantry today) is reached with no `Authorization` header at all,
   * which is a different thing from reaching it with one this process invented.
   *
   * It is *never* the caller's own credential. See `proxy.ts` for why, and for
   * what would have to be true to change that.
   */
  token?: string;
};

/** Path prefix -> upstream. The whole of routing's configuration. */
export type RouteTable = Record<string, RouteTarget>;

/** One request's answer: the prefix that claimed it and where it goes. */
export type ResolvedRoute = {
  /** The prefix that claimed the path, for the log line on a failure. */
  prefix: string;
  baseUrl: string;
  token?: string;
};

/**
 * The prefix every routed path lives under.
 *
 * `/v1/` rather than anything else, and not for tidiness. The pass-through is
 * mounted on `/v1/*`, which is where the token gate and the limiter already
 * are, so a routed request is authenticated and counted without either this
 * module knowing anything about either. It also means a configured prefix can
 * never reach `/auth/*`, `/healthz` or `/readyz`: the browser surface and the
 * probes are outside the API surface by construction rather than by a rule
 * somebody has to remember.
 */
export const ROUTE_MOUNT = "/v1/*";

/** The one path under the mount that guard itself serves. */
const GUARD_OWNED = "/v1/me";

/**
 * A table, validated.
 *
 * Returns a fresh object rather than the one it was handed, so a caller cannot
 * reach in afterwards and add a prefix that was never checked — the same reason
 * `limitTable` returns a copy.
 */
export function routeTable(table: RouteTable): RouteTable {
  const entries = Object.entries(table ?? {});
  if (entries.length === 0) {
    throw new RangeError(
      "routeTable: a route table must name at least one prefix. An empty one forwards nothing, and " +
        "an operator who meant to configure routing would never find out from a 404.",
    );
  }

  const checked: RouteTable = {};
  for (const [prefix, target] of entries) {
    const key = checkPrefix(prefix);
    checked[key] = { baseUrl: checkBaseUrl(key, target?.baseUrl), token: checkToken(key, target?.token) };
  }

  return checked;
}

/**
 * The upstream for one path, or null when nothing claims it.
 *
 * Longest matching prefix wins, on a path-segment boundary — the same rule
 * `resolveLimit` applies, and deliberately the same *rule* rather than the same
 * code: the two tables answer the same question about the same prefixes, and a
 * route that is rate limited under one reading and not under the other is a
 * limit nobody can reason about. `/v1/pantry` claims `/v1/pantry` and
 * `/v1/pantry/items` and not `/v1/pantryx`, so a new service cannot inherit a
 * mount by sharing a name with an old one.
 *
 * A prefix of exactly `/v1` claims everything under the API surface, including
 * guard's own `/v1/me`. That is allowed, and `/v1/me` is still served by guard:
 * it is registered before the pass-through, so Hono answers it first and the
 * mount never runs. `checkPrefix` refuses the prefix that *is* `/v1/me`,
 * because a table entry that can never fire is a claim, not a configuration.
 */
export function resolveRoute(table: RouteTable, path: string): ResolvedRoute | null {
  const target = pathname(path);
  let best: ResolvedRoute | null = null;
  let bestLength = -1;

  for (const [prefix, upstream] of Object.entries(table)) {
    if (prefix.length <= bestLength || !claims(prefix, target)) continue;

    best = { prefix, baseUrl: upstream.baseUrl, ...(upstream.token === undefined ? {} : { token: upstream.token }) };
    bestLength = prefix.length;
  }

  return best;
}

/** The path, without the query or the fragment. */
function pathname(path: string): string {
  const cut = path.search(/[?#]/);

  return cut === -1 ? path : path.slice(0, cut);
}

function claims(prefix: string, path: string): boolean {
  if (prefix === "/") return path === "/";

  return path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`);
}

/**
 * A prefix is a path under the API surface, never a pattern.
 *
 * The trailing slash is left alone because it is meaningful to the matcher, and
 * `/v1` is allowed because it is the whole surface. What is refused is anything
 * that could not be reached, could match more than a subtree, or could carry a
 * traversal out of the mount before a request is ever made.
 */
function checkPrefix(prefix: string): string {
  assertNonEmptyString(prefix, "routeTable: route prefixes");

  if (!prefix.startsWith("/")) {
    throw new RangeError(`routeTable: route prefixes must be absolute paths, got ${JSON.stringify(prefix)}`);
  }
  if (prefix.includes("*") || prefix.includes("?")) {
    throw new RangeError(
      `routeTable: route prefixes must be paths and not patterns, got ${JSON.stringify(prefix)}. ` +
        `The whole subtree under a prefix is routed; a glob would be a second matching language to get wrong.`,
    );
  }
  if (!isUnderMount(prefix)) {
    throw new RangeError(
      `routeTable: route prefixes must live under ${ROUTE_MOUNT}, got ${JSON.stringify(prefix)}. ` +
        `The pass-through is mounted there, so a prefix elsewhere could never match — a route that ` +
        `silently forwards nothing.`,
    );
  }
  if (prefix === GUARD_OWNED) {
    throw new RangeError(
      `routeTable: ${GUARD_OWNED} is guard's own route and is served before the pass-through, so a ` +
        `table claiming it describes a route that can never run.`,
    );
  }
  if (prefix.split("/").some((segment) => segment === "." || segment === ".." || decodeSegment(segment) === "..")) {
    throw new RangeError(
      `routeTable: route prefixes must not contain a traversal segment, got ${JSON.stringify(prefix)}`,
    );
  }

  return prefix;
}

/** `/v1` and anything under it. */
function isUnderMount(prefix: string): boolean {
  return prefix === "/v1" || prefix.startsWith("/v1/");
}

/**
 * An upstream's base URL, reduced to an origin.
 *
 * Mirrors `parseIdentityUrl`, and for the same reasons stated there: no path
 * (the caller's path is appended), no trailing slash (it would join into
 * `//v1/items`), and credentials in the authority are refused because a URL
 * that carries a password is a URL that ends up in a log line.
 */
function checkBaseUrl(prefix: string, value: string): string {
  assertNonEmptyString(value, `routeTable: ${prefix} baseUrl`);

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RangeError(`routeTable: ${prefix} baseUrl must be an absolute URL, got ${JSON.stringify(value)}`);
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RangeError(`routeTable: ${prefix} baseUrl must be http(s), got ${JSON.stringify(value)}`);
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new RangeError(
      `routeTable: ${prefix} baseUrl must be a base URL with no path, got ${JSON.stringify(value)}. ` +
        `The caller's path is appended to it.`,
    );
  }
  if (url.search !== "" || url.hash !== "") {
    throw new RangeError(
      `routeTable: ${prefix} baseUrl must carry no query or fragment, got ${JSON.stringify(value)}`,
    );
  }
  if (url.username !== "" || url.password !== "") {
    throw new RangeError(
      `routeTable: ${prefix} baseUrl must not carry credentials, got ${JSON.stringify(value)}. ` +
        `A credential belongs in the table's token, not in an authority that gets written to a log.`,
    );
  }

  return url.origin;
}

/**
 * A bearer token, or nothing.
 *
 * Whitespace and control characters are refused rather than escaped. This value
 * is written into a request header verbatim, so a newline here is header
 * injection configured on purpose — the same class of defect as a caller's CRLF,
 * arriving from the one place an operator trusts.
 */
function checkToken(prefix: string, value: string | undefined): string | undefined {
  if (value === undefined) return undefined;

  assertNonEmptyString(value, `routeTable: ${prefix} token`);
  if (/[\s\u0000-\u001f\u007f]/.test(value)) {
    throw new RangeError(
      `routeTable: ${prefix} token must not contain whitespace or control characters. It is written ` +
        `into an Authorization header verbatim.`,
    );
  }

  return value;
}

/**
 * One path segment, percent-decoded once.
 *
 * `%2e%2e` is `..`, and a prefix carrying it is a traversal that has not
 * happened yet: the pass-through rebuilds the upstream path from decoded
 * segments, so a configured prefix is checked in the same notation a caller's
 * path arrives in.
 */
function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}