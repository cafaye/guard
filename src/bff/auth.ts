// The browser-facing half of the gateway: a BFF.
//
// A browser talks to guard and to nothing else. It never holds identity's token,
// never sees identity's endpoints, and never gets to choose a credential: it
// holds a session id out of a `__Host-` cookie that guard minted, and guard
// swaps that id for the token when a request needs one. A token in a page is a
// token a cross-site script can read; a session id in an HttpOnly cookie is not.
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Context, Handler, MiddlewareHandler } from "hono";
import { problem, type FieldError, type Problem } from "../problem";
import type { Probe, ProbeStatus } from "../probe";
import { memorySessionStore, type SessionStore } from "./session";

/**
 * The session cookie's name. The `__Host-` prefix is a contract the browser
 * enforces — Secure, `Path=/`, and no `Domain` — which makes the cookie
 * impossible for a subdomain or a plain-HTTP sibling origin to set or overwrite.
 * That is the cookie-fixation vector a plain `session` cookie leaves open, and
 * it is why this is a constant rather than a value in the handlers.
 */
export const SESSION_COOKIE = "__Host-bff-session";

/** Where identity is when nothing says otherwise: the compose stack. */
export const DEFAULT_IDENTITY_URL = "http://localhost:8080";

const DEFAULT_IDENTITY_TIMEOUT_MS = 5_000;

/**
 * The most of a request body guard will hold: an address and a password, and
 * the same 4 KiB identity caps its own bodies at. A registration is well under
 * 1 KB; the rest is room for encoding and for a client that sends a field guard
 * will not forward.
 */
const MAX_BODY_BYTES = 4 << 10;

/** identity's routes, as the guard-03 contract fixes them. */
const IDENTITY = {
  register: "/v1/users",
  session: "/v1/session",
  me: "/v1/me",
  healthz: "/healthz",
} as const;

/**
 * `fetch`, injectable so the suite never opens a socket. A test double for the
 * dependency beats a listening port: the assertions here are about what guard
 * sends and what it does with the answer, and a real server would only add the
 * network's opinions to both.
 */
export type FetchFn = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export type BffOptions = {
  /**
   * identity's base URL, http(s) and with no path. The four routes above are
   * appended by guard, which is why this is not `IDENTITY_ISSUER`: the issuer is
   * the https origin tokens are *verified* against, and this is the service
   * address sessions are *requested* from.
   */
  identityUrl: string;
  /** Where sessions live. Defaults to the in-memory v0 store. */
  sessions?: SessionStore;
  /** Defaults to the global `fetch`. */
  fetch?: FetchFn;
  /** How long one call to identity may take. Default 5000. */
  timeoutMs?: number;
};

export type BffAuth = {
  register: Handler;
  login: Handler;
  logout: Handler;
  me: Handler;
  /** Mount on a mutating route: 403 unless the request is provably same-origin. */
  requireSameOrigin: MiddlewareHandler;
};

/**
 * Builds the /auth surface.
 *
 * Configuration is validated here, at construction, for the same reason the JWT
 * verifier validates its own: `IDENTITY_URL=identity:8080` has to be a refusal
 * to boot, not a 503 on every login the operator then has to read logs to
 * diagnose.
 */
export function createBffAuth(options: BffOptions): BffAuth {
  const identityUrl = parseIdentityUrl(options.identityUrl);
  const timeoutMs = options.timeoutMs ?? DEFAULT_IDENTITY_TIMEOUT_MS;
  const sessions = options.sessions ?? memorySessionStore();
  const send = options.fetch ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));

  assertPositiveInteger(timeoutMs, "timeoutMs");

  /** One call to identity, or null when there was no answer to have. */
  async function call(
    path: string,
    init: { method: string; body?: string; token?: string },
  ): Promise<Response | null> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (init.body !== undefined) headers["content-type"] = "application/json";
    if (init.token !== undefined) headers.authorization = `Bearer ${init.token}`;

    try {
      return await within(
        send(`${identityUrl}${path}`, { method: init.method, headers, body: init.body, signal: AbortSignal.timeout(timeoutMs) }),
        timeoutMs,
        `${init.method} ${path}`,
      );
    } catch (error) {
      // The URL, the status and the socket error are the platform's to know.
      // An anonymous browser is not.
      console.error("guard: identity call failed", error);
      return null;
    }
  }

  const register: Handler = async (c) => {
    const submitted = await rawJsonObject(c);
    if (submitted === null) return problem(c, notAnObject());
    if ("tooLarge" in submitted) return problem(c, tooLarge());

    const response = await call(IDENTITY.register, { method: "POST", body: submitted.body });
    if (response === null) return problem(c, unreachable());

    if (response.status === 201) {
      const user = userOf(await jsonOf(response));
      return user === null ? problem(c, unusable()) : c.json(user, 201);
    }
    if (response.status === 422) {
      return problem(c, {
        status: 422,
        code: "validation_failed",
        detail: "the request has an invalid field",
        // A sign-up form renders these; dropping them leaves the browser saying
        // "something went wrong" about a field identity named exactly.
        errors: fieldErrorsOf(await jsonOf(response)),
      });
    }
    if (response.status === 409) {
      return problem(c, { status: 409, code: "conflict", detail: "an account already exists for that email address" });
    }

    // Anything else — a 200, a 500, a body that is not a user — is identity
    // saying something this contract does not cover, and guessing at it would
    // be guard inventing an account.
    return problem(c, unusable());
  };

  const login: Handler = async (c) => {
    const submitted = await rawJsonObject(c);
    if (submitted === null) return problem(c, notAnObject());
    if ("tooLarge" in submitted) return problem(c, tooLarge());

    const response = await call(IDENTITY.session, { method: "POST", body: submitted.body });
    if (response === null) return problem(c, unreachable());
    if (response.status !== 200) return loginRefusal(c, response);

    const session = sessionOf(await jsonOf(response));
    // A session with no expiry, an unparseable one, or one already in the past
    // is not a session: the cookie would be set and the very next request would
    // refuse it, which is a login that reports success and signs the user out.
    if (session === null || session.expiresAt <= Date.now()) return problem(c, unusable());

    // Minted here, never accepted from the caller. Fixation needs an id the
    // attacker knows first, and `randomUUID` is the reason they cannot.
    const sessionId = crypto.randomUUID();
    await sessions.put(sessionId, session);

    setCookie(c, SESSION_COOKIE, sessionId, { ...COOKIE, expires: new Date(session.expiresAt) });

    // The body says when the session runs out and nothing else. Echoing the
    // token would hand the page a long-lived credential that the HttpOnly cookie
    // exists to keep away from it.
    return c.json({ expires_at: new Date(session.expiresAt).toISOString() }, 200);
  };

  const logout: Handler = async (c) => {
    const sessionId = getCookie(c, SESSION_COOKIE);
    if (sessionId === undefined) {
      // identity answers 401 here too, for the same reason: a 204 would report
      // that something happened when there was no session to end.
      return problem(c, { status: 401, code: "unauthorized", detail: "no session cookie was presented" });
    }

    const session = await sessions.get(sessionId);
    if (session === null) {
      // A cookie the store has forgotten — a restart, a swept map. The browser
      // is not signed in and there is provably nothing to revoke, which is the
      // state the caller asked for. Refusing is what makes sign-out look broken.
      clearCookie(c);
      return c.body(null, 204);
    }

    // Dropped locally first, on purpose. Failing to sign a browser out is worse
    // than a token that outlives its revocation until `exp`, and the caller is
    // told about the difference below rather than left to assume it.
    await sessions.delete(sessionId);
    clearCookie(c);

    const response = await call(IDENTITY.session, { method: "DELETE", token: session.token });
    // 204 is a revocation. 401 and 404 are a token identity has already
    // forgotten, which is the same end state reached by another route.
    const revoked = response !== null && [204, 401, 404].includes(response.status);

    return revoked ? c.body(null, 204) : problem(c, unreachable());
  };

  const me: Handler = async (c) => {
    const sessionId = getCookie(c, SESSION_COOKIE);
    if (sessionId === undefined) {
      return problem(c, { status: 401, code: "unauthorized", detail: "no session cookie was presented" });
    }

    const session = await sessions.get(sessionId);
    // Cleared on the way out, not left in place: a cookie whose record is gone
    // can never work again, and a browser that keeps presenting it is a signed
    // out user whose every request looks like a server that forgot them.
    if (session === null) {
      clearCookie(c);
      return problem(c, { status: 401, code: "unauthorized", detail: "the session is no longer valid" });
    }

    const response = await call(IDENTITY.me, { method: "GET", token: session.token });
    if (response === null) return problem(c, unreachable());

    if (response.status === 401) {
      // identity withdrew it — a sign-out everywhere, or a revoked session.
      // Dropping the record makes that true from this request on, rather than at
      // the token's expiry. An *outage* below does not: that is not a
      // revocation, and treating it as one would sign everybody out whenever
      // identity hiccups.
      await sessions.delete(sessionId);
      clearCookie(c);
      return problem(c, { status: 401, code: "unauthorized", detail: "the session is no longer valid" });
    }

    if (response.status !== 200) return problem(c, unusable());

    const user = userOf(await jsonOf(response));
    return user === null ? problem(c, unusable()) : c.json(user, 200);
  };

  const requireSameOrigin: MiddlewareHandler = async (c, next) => {
    if (!isSameOrigin(c)) {
      return problem(c, { status: 403, code: "forbidden", detail: "this request is not from the same origin" });
    }
    await next();
  };

  return { register, login, logout, me, requireSameOrigin };
}

/**
 * Reports whether identity is reachable, for `/readyz`.
 *
 * identity's own liveness endpoint rather than one of the four auth routes: a
 * probe that authenticates would need a credential to answer, and a readiness
 * check that can fail on its own credentials is not a readiness check.
 */
export function identityProbe(options: BffOptions): Probe {
  const identityUrl = parseIdentityUrl(options.identityUrl);
  const timeoutMs = options.timeoutMs ?? DEFAULT_IDENTITY_TIMEOUT_MS;
  const send = options.fetch ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));

  return async (): Promise<ProbeStatus> => {
    try {
      const response = await within(
        send(`${identityUrl}${IDENTITY.healthz}`, { signal: AbortSignal.timeout(timeoutMs) }),
        timeoutMs,
        `GET ${IDENTITY.healthz}`,
      );
      return response.ok ? "ok" : "unavailable";
    } catch (error) {
      console.error("guard: identity probe failed", error);
      return "unavailable";
    }
  };
}

/**
 * Every attribute the session cookie is set with, in one place.
 *
 * The deletion repeats them verbatim, because a browser matches a cookie to
 * delete on name, domain and path: a deletion missing one of them leaves the
 * original in place, which is the precise bug that makes "sign out" appear to do
 * nothing. `sameSite: Lax` and not `Strict` because a Strict cookie is not sent
 * on the top-level navigation a user follows straight after signing in.
 */
const COOKIE = { path: "/", secure: true, httpOnly: true, sameSite: "Lax" } as const;

function clearCookie(c: Context): void {
  deleteCookie(c, SESSION_COOKIE, { ...COOKIE });
}

/**
 * identity's refusals, as core envelopes.
 *
 * Each route maps only the statuses identity documents for *that* route; a
 * status the contract does not cover is a 503 rather than a guess, because a
 * guess here is how a 423 turns into a 401 and a lockout turns into a retry loop
 * the caller owns.
 */
function loginRefusal(c: Context, response: Response): Response {
  if (response.status === 401) {
    // One sentence for every refused credential. Varying it per case is how a
    // login endpoint becomes an account-enumeration oracle.
    return problem(c, { status: 401, code: "unauthorized", detail: "email or password is not correct" });
  }

  if (response.status === 423) {
    // The window travels with the answer. Collapsing the lockout into the 401
    // above would tell someone with the right password to try again, and be
    // refused again, for a quarter of an hour.
    const retryAfter = response.headers.get("Retry-After");
    if (retryAfter !== null && /^\d+$/.test(retryAfter)) c.header("Retry-After", retryAfter);

    return problem(c, { status: 423, code: "account_locked", detail: "too many failed sign-in attempts for this account" });
  }

  return problem(c, unusable());
}

/**
 * The caller's body: bytes guard did not touch, as a JSON object, within the cap
 * — or null when it is not one of those three things.
 *
 * Only "is this an object" is decided here. Whether an address is deliverable
 * and a password strong enough is identity's call, in one place, under the same
 * rules every other client of identity gets — a second set of rules in the
 * gateway is a second answer to "what is a valid password".
 */
async function rawJsonObject(c: Context): Promise<{ body: string } | { tooLarge: true } | null> {
  const raw = await readBounded(c.req.raw, MAX_BODY_BYTES);
  if (raw === null) return null;
  if (raw === TOO_LARGE) return { tooLarge: true };

  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }

  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return { body: raw };
}

/** Distinguishable from a body, which is also a string. */
const TOO_LARGE = Symbol("body too large");

/**
 * Reads at most `limit` bytes, or says the body is bigger.
 *
 * The cap is enforced at the reader rather than after `request.text()`, because
 * `text()` is the whole body in memory: an unauthenticated caller would then
 * choose how much of this process a single request holds. identity caps its own
 * bodies at 4 KiB, so a request that big is one identity would refuse to read
 * anyway — and refusing it here means guard never held it either.
 *
 * A `Content-Length` over the limit is answered from the header alone, so the
 * common case costs no read at all.
 */
async function readBounded(request: Request, limit: number): Promise<string | null | typeof TOO_LARGE> {
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > limit) return TOO_LARGE;

  const reader = request.body?.getReader();
  if (reader === undefined) return null;

  const chunks: Uint8Array[] = [];
  let size = 0;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;

    size += value.byteLength;
    // Cancelled rather than drained: the rest of the body is not going to be
    // used, and a caller that keeps sending it gets a closed connection.
    if (size > limit) {
      await reader.cancel();
      return TOO_LARGE;
    }
    chunks.push(value);
  }

  return new TextDecoder().decode(concat(chunks));
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const joined = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.byteLength, 0));
  let at = 0;
  for (const chunk of chunks) {
    joined.set(chunk, at);
    at += chunk.byteLength;
  }
  return joined;
}

/** A dependency's answer, or null for something that is not JSON at all. */
async function jsonOf(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * `{id, email}` and nothing else.
 *
 * An allowlist rather than a filter: a field identity adds next month must not
 * reach a browser response today by being copied, and a digest that appears in
 * the user document has no business in a page either.
 */
function userOf(document: unknown): { id: string; email: string } | null {
  if (typeof document !== "object" || document === null) return null;

  const { id, email } = document as { id?: unknown; email?: unknown };
  if (typeof id !== "string" || id === "" || typeof email !== "string" || email === "") return null;

  return { id, email };
}

/** A token and the instant it stops being one, or null if either is unusable. */
function sessionOf(document: unknown): { token: string; expiresAt: number } | null {
  if (typeof document !== "object" || document === null) return null;

  const { token, expires_at: expires } = document as { token?: unknown; expires_at?: unknown };
  if (typeof token !== "string" || token === "" || typeof expires !== "string") return null;

  const expiresAt = Date.parse(expires);
  if (Number.isNaN(expiresAt)) return null;

  return { token, expiresAt };
}

/**
 * identity's per-field failures, kept only if they are shaped like core's.
 *
 * identity is a trusted dependency, but this array is data guard renders into a
 * page, and a field name is not a place to accept an arbitrary document.
 */
function fieldErrorsOf(document: unknown): FieldError[] | undefined {
  const { errors } = (typeof document === "object" && document !== null ? document : {}) as { errors?: unknown };
  if (!Array.isArray(errors)) return undefined;

  const kept = errors.filter(isFieldError);
  return kept.length > 0 ? kept : undefined;
}

function isFieldError(value: unknown): value is FieldError {
  if (typeof value !== "object" || value === null) return false;

  const { field, code } = value as { field?: unknown; code?: unknown };
  return typeof field === "string" && typeof code === "string";
}

/**
 * Whether a request provably comes from this origin.
 *
 * Two signals, and a request has to produce one of them:
 *
 *   `Sec-Fetch-Site`  set by the user agent and not by the page, so it is an
 *                     assertion no cross-site requester can make. Only
 *                     `same-origin` passes. `cross-site` is the attack, and
 *                     `same-site` is a sibling subdomain — which a Lax cookie
 *                     *is* sent to, so a subdomain that can post to its parent
 *                     has something to spend. `none` means the agent could not
 *                     attribute the request to a page, which is not a claim of
 *                     same-origin, and nothing in this flow needs it.
 *
 *   `Origin`          the fallback for an agent that sends no fetch metadata.
 *                     Compared by host, not by origin: a TLS-terminating proxy
 *                     rewrites the scheme guard sees while the browser's header
 *                     still says https, and comparing it would 403 every real
 *                     browser. The host is the one the browser addressed the
 *                     request to, and a cross-site requester cannot choose it.
 *
 * A request with neither is refused. Every browser sends one of the two, and a
 * client that sends neither has no ambient credential to abuse — but it is also
 * not *provably* same-origin, and this gate refuses what it cannot prove. curl
 * and the test suite state their origin; a browser never has to.
 */
function isSameOrigin(c: Context): boolean {
  const site = c.req.header("sec-fetch-site");
  const origin = c.req.header("origin");

  // Compared as a token, not as a string: a user agent that changed the casing
  // of a header value would otherwise lock every browser out of sign-in, and
  // case-folding four known tokens is not something an attacker can forge.
  if (site !== undefined && site.trim().toLowerCase() !== "same-origin") return false;
  if (origin !== undefined && hostOf(origin) !== hostOf(c.req.url)) return false;

  // The request has to state one of them, and when it states both they have to
  // agree. A browser sends them consistently, so a disagreement is not a
  // browser: it is a client that chose what each header says, and the gate
  // believes the stricter of the two rather than the friendlier one.
  return site !== undefined || origin !== undefined;
}

/** A URL's `host:port`, or null for anything that is not a URL — `null` included. */
function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

/**
 * One call, bounded in time.
 *
 * The signal cancels a real fetch and the race bounds the handler even if the
 * fetch ignores it — the difference between a request that fails and a process
 * that stops answering. The timer is cleared either way, so a fast identity
 * leaves nothing pending behind it.
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

/**
 * identity's base URL, reduced to an origin.
 *
 * No path, because the routes above are appended to it: a base carrying one
 * would put `/v1/session` somewhere nobody is serving it. The trailing slash is
 * dropped, because it is what an operator types out of habit and keeping it
 * would join into `//v1/users`.
 */
function parseIdentityUrl(value: string): string {
  const text = typeof value === "string" ? value.trim() : "";
  if (text === "") throw new RangeError("createBffAuth: identityUrl must be a non-empty string");

  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new RangeError(`createBffAuth: identityUrl must be an absolute URL, got ${JSON.stringify(value)}`);
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RangeError(`createBffAuth: identityUrl must be http(s), got ${JSON.stringify(value)}`);
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new RangeError(`createBffAuth: identityUrl must be a base URL with no path, got ${JSON.stringify(value)}`);
  }

  return url.origin;
}

/**
 * Two 503s, deliberately not one.
 *
 * identity being unreachable and identity answering something unusable are
 * different failures with different fixes — a restarted service against a wrong
 * `IDENTITY_URL` — and an operator reading a 503 in a browser is the only one
 * who will ever see which it was. The URL and the status that produced it are in
 * the log either way.
 */
function unreachable(): Problem {
  return { status: 503, code: "unavailable", detail: "the authentication service could not be reached" };
}

function unusable(): Problem {
  return { status: 503, code: "unavailable", detail: "the authentication service answered with something unusable" };
}

function notAnObject(): Problem {
  return { status: 400, code: "invalid_json", detail: "the request body must be a JSON object" };
}

function tooLarge(): Problem {
  return {
    status: 413,
    code: "payload_too_large",
    detail: `the request body is larger than ${MAX_BODY_BYTES} bytes`,
  };
}

function assertPositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new RangeError(`createBffAuth: ${field} must be an integer >= 1, got ${String(value)}`);
  }
}
