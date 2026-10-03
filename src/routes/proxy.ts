// The pass-through: a path prefix, an upstream, and guard's own credential.
//
// This is the half of routing that touches the network, and it is deliberately
// thin. `fetch` is the tool — a proxy library would be a dependency with no
// cause, in a repository whose rule is that a dependency has to earn itself —
// and there is no retry, no circuit breaker and no health check, because each
// of those is a packet that says what it costs and this one is an hour.
//
// ## THE FOUR THINGS A FORWARDER HAS TO GET RIGHT
//
// `site/src/lib/upstream.ts` arrived at the same four from the other direction
// (a browser reaching identity through a Next.js route handler), and the
// numbering is borrowed deliberately — a forwarder that gets any of them wrong
// is an open proxy, and the two repositories are solving one problem at two
// ends of the same hop:
//
//   1. ONE CONFIGURED DESTINATION, NEVER A CALLER-SUPPLIED HOST. The upstream
//      comes out of the validated table and the remainder of the path is
//      appended to it. There is no code path that could build a fetch out of a
//      header, a query, a body or a segment.
//
//   2. THE UPSTREAM PATH IS REBUILT, NEVER FORWARDED AS RECEIVED. Every
//      segment is decoded, checked and re-encoded (`upstreamPath`), so a
//      traversal is not filtered — it is not expressible. `%2e%2e` survives
//      WHATWG URL normalisation, so this is the check that matters.
//
//   3. AN UPSTREAM FAILURE IS GUARD'S TO TRANSLATE. A 5xx, a 3xx or a dead
//      socket becomes a fixed 503 and nothing else. `ECONNREFUSED 10.0.3.7:8080`
//      is the internal topology of a fleet and it must not reach whoever asked.
//
//   4. THE CREDENTIAL IS GUARD'S. See below.
//
// ## THE CREDENTIAL RULE, WHICH IS THE SECURITY CONTENT HERE
//
// guard attaches the credential for the upstream it is calling. The caller's
// inbound `Authorization` is **never** copied to an internal service, and
// neither is their `Cookie`.
//
// The reason is what forwarding it would turn guard into. If a caller can set
// an arbitrary `Authorization` and have it reach pantry, then guard is a
// confused deputy: the caller authenticates *to guard* and then chooses who
// they are *downstream*. Every property "guard is the only door" rests on —
// that the credential a service sees is one guard issued or verified — is gone,
// and an attacker does not need a token for the service at all, only a valid
// one for the edge and a target of their choosing. `GET /auth/me` already holds
// this line for identity: it takes the **stored** token from the session, never
// one from the request. This is the same shape pointed at a service rather than
// at a route.
//
// So the outbound header set is an allowlist of two (`content-type`, `accept`)
// plus whatever the table's entry carries. A header this file does not name
// cannot be a smuggling channel, which is a property a deny list never has: a
// deny list has to have thought of `Authorization`, `Cookie`, `X-Forwarded-For`
// and every header a future proxy invents.
//
// What that costs, stated plainly because it is the open half: an upstream
// cannot tell which caller sent a request. The per-upstream `token` is a
// service credential, not a delegation, and no header here asserts who the
// caller was. Propagating a verified principal is a deliberate decision with
// both halves written — guard asserting it *and* the service verifying it —
// and it is not this packet.
import type { Context, MiddlewareHandler } from "hono";
import { problem, type Problem } from "../problem";
import { resolveRoute, type RouteTable } from "./table";

/** Where a routed request goes, when nothing says otherwise: five seconds. */
const DEFAULT_UPSTREAM_TIMEOUT_MS = 5_000;

/**
 * `fetch`, injectable so the suite never opens a socket — the same reason
 * `bff/auth.ts` has one. The assertions here are about what guard sends and
 * what it does with the answer; a listening upstream would add the network's
 * opinions to both.
 */
export type ProxyFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export type ProxyOptions = {
  /** Already validated, or validated again here; `routeTable` is cheap. */
  routes: RouteTable;
  /** Defaults to the global `fetch`. */
  fetch?: ProxyFetch;
  /** How long one call to a service may take. */
  timeoutMs?: number;
};

/**
 * The request headers that cross to a service.
 *
 * Two, and the list is the control: `accept` so a service that answers
 * `application/problem+json` is asked for it, and `content-type` so a body
 * stays the shape it was sent as. Everything else the caller sent is dropped —
 * `authorization` and `cookie` by the rule above, and `host`,
 * `x-forwarded-for` and the rest because a caller-chosen header that reaches an
 * internal service is an input to something nobody has read yet.
 */
const FORWARDED_REQUEST_HEADERS = ["content-type", "accept"] as const;

/** The response headers that cross back. One, for the same reason. */
const FORWARDED_RESPONSE_HEADERS = ["content-type"] as const;

/**
 * The pass-through, mounted on `/v1/*`.
 *
 * A path nothing claims calls `next()` rather than refusing, which is what lets
 * guard's own `/v1/me` — registered before this mount, so it answers first —
 * and every unrouted path keep behaving exactly as they did before routing
 * existed. A path that cannot be rebuilt into a service path also calls
 * `next()`, and lands on the same 404 an unrouted path does: it is not a route
 * this gateway serves, which is a truer sentence than one invented here.
 */
export function createRouteProxy(options: ProxyOptions): MiddlewareHandler {
  const table = options.routes;
  const timeoutMs = options.timeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
  const send = options.fetch ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));

  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
    throw new RangeError(`createRouteProxy: timeoutMs must be an integer >= 1, got ${String(timeoutMs)}`);
  }

  return async (c, next) => {
    const url = new URL(c.req.url);
    const route = resolveRoute(table, url.pathname);
    if (route === null) return next();

    const path = upstreamPath(route.prefix, url.pathname);
    if (path === null) return next();

    const target = `${route.baseUrl}${path}${url.search}`;
    const response = await call(send, target, c, route.token, timeoutMs);

    // A 2xx or a 4xx is the service's own contract and crosses unchanged: a 401
    // that became a 200 would report a refusal as a success, and a 422 that
    // became a 400 would drop the field errors a form turns into sentences.
    // Everything else — 3xx and 5xx — is a `Location` or an error page from
    // behind the edge, and it is translated.
    if (response === null) return problem(c, unreachable());
    if (isRelayable(response.status)) return relay(response);

    return problem(c, unusable(target, response.status, await shapeOf(response)));
  };

  /**
   * One call to a service, or null when there was no answer to have.
   *
   * The signal cancels a real fetch and `within` bounds the handler even if the
   * fetch ignores it — the difference between a request that fails and a
   * process that stops answering. No retry: a retry multiplies load on a service
   * that is already failing, and the limiter counts one attempt, so a retry
   * would make the accounting describe traffic guard never refused.
   */
  async function call(
    send: ProxyFetch,
    target: string,
    c: Context,
    token: string | undefined,
    timeoutMs: number,
  ): Promise<Response | null> {
    try {
      return await within(
        send(target, {
          method: c.req.method,
          headers: outboundHeaders(c, token),
          body: bodyOf(c),
          // `manual`, because the default follows a redirect — and a `Location`
          // an internal service answers with is an address that is not on the
          // internet. Nothing is followed and nothing is relayed.
          redirect: "manual",
          signal: AbortSignal.timeout(timeoutMs),
        }),
        timeoutMs,
        `${c.req.method} ${target}`,
      );
    } catch (error) {
      // The URL, the socket error and the stack go to the log. They are the
      // platform's to know and an authenticated caller is not to be told.
      console.error(`guard: upstream ${target} could not be reached`, error);
      return null;
    }
  }
}

/**
 * The headers guard sends, built from an allowlist and its own credential.
 *
 * The credential is `Bearer` with the table's token and never the caller's: when
 * a table entry has no token, no `Authorization` header is sent at all, which is
 * a different thing from sending one this process invented. A caller's
 * `Authorization` and `Cookie` are not in the list and so cannot cross, and the
 * test in `proxy.test.ts` asserts on the recorded request rather than on this
 * function.
 */
function outboundHeaders(c: Context, token: string | undefined): Headers {
  const headers = new Headers();

  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = c.req.header(name);
    if (value !== undefined) headers.set(name, value);
  }
  if (token !== undefined) headers.set("authorization", `Bearer ${token}`);

  return headers;
}

/**
 * The caller's body, streamed, or nothing for a method that cannot carry one.
 *
 * Streamed rather than buffered because a proxy that reads a body in order to
 * hand it straight on is holding a caller's megabytes in memory for no reason;
 * `duplex` is set because the Web-standard `fetch` requires it for a stream body
 * and the runtime that does not need it ignores it.
 */
function bodyOf(c: Context): ReadableStream<Uint8Array> | null | undefined {
  if (c.req.method === "GET" || c.req.method === "HEAD") return undefined;

  return c.req.raw.body ?? undefined;
}

/**
 * The service's path, rebuilt from the caller's segments.
 *
 * Structural rather than filtered, which is the property: each segment is
 * decoded, refused if it is `.`, `..`, an empty segment or one that contains a
 * separator, and re-encoded. A traversal, an absolute URL in a segment and a
 * doubled slash are not rejected by a list here — after this function they are
 * not expressible. `%2e%2e` is the case that matters, because a percent-encoded
 * dot segment survives the URL parser and reaches guard as three ordinary
 * characters.
 *
 * `null` means "not a path this gateway serves", which the caller is told by the
 * same 404 an unrouted path gets.
 */
export function upstreamPath(prefix: string, path: string): string | null {
  const rest = path.slice(prefix.length);
  if (rest === "") return "/";
  if (!rest.startsWith("/")) return null;

  // A trailing slash is not a segment. `/v1/pantry/items/` and
  // `/v1/pantry/items` are the same question and every service this platform has
  // answers them the same way; an *interior* empty segment is a doubled slash,
  // which is not a path and is refused below rather than quietly collapsed.
  const segments = rest.slice(1).split("/");
  if (segments[segments.length - 1] === "") segments.pop();

  const out: string[] = [];
  for (const raw of segments) {
    const segment = decodeSegment(raw);
    if (segment === null || segment === "" || segment === "." || segment === ".." || /[/\\]/.test(segment)) return null;

    out.push(encodeURIComponent(segment));
  }

  return out.length === 0 ? "/" : `/${out.join("/")}`;
}

/** A decoded segment, or null for one that is not valid percent-encoding. */
function decodeSegment(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * Whether a status crosses, or is translated.
 *
 * A 2xx or a 4xx is the service's own contract and reaches the caller as it is:
 * a 401 that became a 200 reports a refusal as a success, and a 422 that became
 * a 400 drops the field errors a form turns into sentences. A 3xx and a 5xx are
 * a `Location` and an error page from behind the edge, and neither belongs to the
 * caller.
 *
 * Stated as its own predicate because it was a range check once, and a range
 * check that reads "300 to 499" is a 200 translated into a 503 — which the first
 * run of `proxy.test.ts` did, in the one sentence this comment is about.
 */
function isRelayable(status: number): boolean {
  return status < 300 || (status >= 400 && status < 500);
}

/**
 * The service's answer, with only the header that says what it is.
 *
 * `set-cookie` is dropped and that is not tidiness: a service answering
 * `Set-Cookie: __Host-bff-session=…` would be writing the browser's BFF session
 * from behind the edge, which is session fixation arriving through the gateway
 * on an origin where the `__Host-` prefix is honoured. `cache-control: no-store`
 * is the one header added rather than forwarded — proxied traffic is
 * authenticated, and a response held in a shared cache between here and the
 * caller is an account's data at rest.
 */
function relay(upstream: Response): Response {
  const headers = new Headers();

  for (const name of FORWARDED_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  headers.set("cache-control", "no-store");

  return new Response(upstream.body, { status: upstream.status, headers });
}

/**
 * Two 503s, deliberately not one, and the same split `bff/auth.ts` draws.
 *
 * A service that cannot be reached is logged by `call`, which is where the
 * socket error is; a service that answered something unusable is logged here,
 * with the target, the status and the *shape* of the body — never the body
 * itself, because a service's error page is exactly where a credential turns up
 * and this repository never writes one down. An operator reading a log at 3am has
 * to be able to tell "the service is down" from "the service is broken", and
 * that difference only exists if it is written down.
 */
function unreachable(): Problem {
  return { status: 503, code: "unavailable", detail: "the service this request needs could not be reached" };
}

function unusable(target: string, status: number, shape: string): Problem {
  console.error(`guard: upstream ${target} answered ${status} (${shape}), which this contract does not relay`);

  return { status: 503, code: "unavailable", detail: "the service this request needs did not answer" };
}

/** What an answer looked like, for a log line and nothing else. */
async function shapeOf(response: Response): Promise<string> {
  let document: unknown;
  try {
    document = await response.clone().json();
  } catch {
    return "not JSON";
  }
  // `null` is separated from a document on purpose: `jsonOf` returns null for a
  // body that was not JSON and `typeof null` is "object", so the obvious test
  // reports an HTML error page as a JSON document.
  return document === null ? "not JSON" : typeof document === "object" ? "a JSON document" : typeof document;
}

/**
 * One call, bounded in time.
 *
 * The same shape as `bff/auth.ts`'s `within`, and for the same reason: the
 * signal cancels a real fetch, and the race bounds the handler even if the fetch
 * ignores it. The timer is cleared either way, so a fast service leaves nothing
 * pending behind it.
 */
async function within<T>(work: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expiry = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not answer within ${ms}ms`)), ms);
  });

  try {
    return await Promise.race([work, expiry]);
  } finally {
    clearTimeout(timer);
  }
}