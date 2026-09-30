// Real RS256 verification against identity's published JWKS.
//
// The contract this implements is the platform auth contract in packet guard-02:
// RS256, keys at `{issuer}/.well-known/jwks.json`, and a rejection for a bad
// signature, an expired token, a wrong `iss`, a wrong `aud`, an `nbf` in the
// future, or a token that is not a JWT at all.
import type { MiddlewareHandler } from "hono";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JWK, type JWTPayload } from "jose";
import { problem, type Problem } from "../problem";

/** The issuer guard falls back to when nothing is configured. */
export const DEFAULT_IDENTITY_ISSUER = "https://identity.localhost";

/** Where identity publishes its keys. Fixed, and appended to the issuer. */
export const JWKS_PATH = "/.well-known/jwks.json";

const DEFAULT_JWKS_CACHE_TTL_MS = 300_000;
const DEFAULT_JWKS_TIMEOUT_MS = 5_000;

/**
 * RS256 and nothing else.
 *
 * The algorithm is a property of the key set identity publishes, not a hint the
 * token carries, so it is pinned here and checked before anything is fetched.
 * core's conventions also allow ES256; widening this is a one-line change, and
 * doing it without identity publishing ES256 keys would only widen the attack
 * surface. See the DECISION NEEDED in cafaye.yml.
 */
const ALGORITHM = "RS256";

/** Space-separated capability claim. core's conventions call it `scopes`. */
const SCOPE_CLAIM = "scope";

export type JwtOptions = {
  /**
   * The issuer, and nothing else: an origin such as `https://identity.localhost`.
   * It is both the expected `iss` and the base the JWKS path is appended to, so
   * a trailing slash is trimmed and a path here is a configuration error.
   */
  issuer: string;
  /** The `client_id` every token must be addressed to. */
  audience: string;
  /** Defaults to `${issuer}/.well-known/jwks.json`. */
  jwksUrl?: string;
  /** How long a fetched key set is reused. Default 300_000. */
  jwksCacheTtlMs?: number;
  /** How long one fetch of the key set may take. Default 5_000. */
  jwksTimeoutMs?: number;
  /** Clock, injected so the cache TTL is testable without sleeping. */
  now?: () => number;
};

/** What a verified request carries. Handlers read this and nothing else. */
export type Principal = {
  /** The user uuid from the `sub` claim. */
  sub: string;
  /** The `scope` claim, split on whitespace. Empty when the claim is absent. */
  scope: string[];
  /**
   * The account the request acts on, from the `account_id` claim, when identity
   * issued one. Absent for a token that has no such claim, which is not an
   * error: a user with no workspace *is* the account, and
   * `accountIdOf` in `./limitKey` falls back to `sub`.
   *
   * It is a field rather than a claim lookup at each use so that the one place
   * that decides what an account is, is the one place that read the token.
   */
  accountId?: string;
  claims: JWTPayload;
};

/** Hono context variables, so a handler gets a typed principal. */
export type AuthEnv = { Variables: { principal: Principal } };

export type JwtVerifier = {
  /** 401 unless the request carries a token this verifier accepts. */
  requireJwt: MiddlewareHandler<AuthEnv>;
  /** 403 for a verified caller without `scope`; mount it after `requireJwt`. */
  requireScope: (scope: string) => MiddlewareHandler<AuthEnv>;
};

/** A verified caller, or the envelope that replaces the response. */
type Outcome = { principal: Principal } | { refusal: Problem };

/** The protected header, read before anything else. */
type Header = { ok: true; kid: string } | { ok: false; refusal: Problem };

/**
 * Builds the verifier. Configuration is validated here, at construction, so a
 * typo in an environment variable is a startup failure rather than a 503 on
 * every request.
 */
export function createJwtVerifier(options: JwtOptions): JwtVerifier {
  const issuer = parseIssuer(options.issuer);
  const audience = parseText(options.audience, "audience");
  // A path here is allowed: an operator who points guard at a key set somewhere
  // other than the issuer's own well-known path means it.
  const jwksUrl = options.jwksUrl ? parseHttpUrl(options.jwksUrl, "jwksUrl").href : `${issuer}${JWKS_PATH}`;
  const ttlMs = options.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL_MS;
  const timeoutMs = options.jwksTimeoutMs ?? DEFAULT_JWKS_TIMEOUT_MS;
  const now = options.now ?? Date.now;

  assertPositiveInteger(ttlMs, "jwksCacheTtlMs");
  assertPositiveInteger(timeoutMs, "jwksTimeoutMs");

  /**
   * The cached key set, and whether the fetch that produced it was the forced
   * one. One verifier per process means one cache: two verifiers would fetch
   * the key set twice and could disagree about whether a rotation has happened.
   */
  let cache: { keys: JWK[]; fetchedAt: number; forced: boolean } | null = null;

  const isFresh = (): boolean => cache !== null && now() - cache.fetchedAt < ttlMs;

  /**
   * Fetches the key set and caches it.
   *
   * `forced` marks the rotation fetch so the same window can rate-limit the next
   * one. Stored only on success: a failed fetch must leave the last good set in
   * place rather than replacing it with an outage.
   */
  async function load(forced: boolean): Promise<JWK[]> {
    const fetched = await fetchKeys();
    cache = { keys: fetched, fetchedAt: now(), forced };
    return fetched;
  }

  async function fetchKeys(): Promise<JWK[]> {
    const response = await fetch(jwksUrl, { signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) throw new Error(`JWKS ${jwksUrl} answered ${response.status}`);

    const document: unknown = await response.json();
    if (!isKeySet(document)) throw new Error(`JWKS ${jwksUrl} is not a key set`);

    return document.keys;
  }

  /** The verified principal, or the reason the caller does not get one. */
  async function authenticate(token: string): Promise<Outcome> {
    const header = decodeHeader(token);
    if (header.ok === false) return { refusal: header.refusal };

    let set: JWK[];
    let fetched = false;
    try {
      if (isFresh() && cache) {
        set = cache.keys;
      } else {
        set = await load(false);
        fetched = true;
      }
    } catch (error) {
      // identity being down is not the caller's fault, and a 401 would tell
      // them to fix a credential that was fine. The reason goes to the log.
      console.error("guard: could not fetch the JWKS", error);
      return { refusal: unavailable() };
    }

    // A key id that is not in the set means one of two things: identity has
    // rotated, or the token names a key that does not exist. The first is
    // answered by one forced refresh per cache window — never a second fetch
    // for a set this request has just read, and never a second one in the same
    // window, so a caller cannot aim every request at identity.
    if (!publishes(set, header.kid)) {
      if (!fetched && cache?.forced !== true) {
        try {
          set = await load(true);
        } catch (error) {
          console.error("guard: could not refresh the JWKS", error);
          return { refusal: unavailable() };
        }
      }
      if (!publishes(set, header.kid)) {
        return { refusal: unauthorized("token was signed by an unknown key") };
      }
    }

    return verifyClaims(token, set);
  }

  /** The verified principal, or the reason the caller does not get one. */
  async function verifyClaims(token: string, set: JWK[]): Promise<Outcome> {
    try {
      const { payload } = await jwtVerify(token, createLocalJWKSet({ keys: set }), {
        issuer,
        audience,
        algorithms: [ALGORITHM],
      });
      return principalOf(payload);
    } catch (error) {
      return { refusal: refusalOf(error) };
    }
  }

  const requireJwt: MiddlewareHandler<AuthEnv> = async (c, next) => {
    const token = bearerToken(c.req.header("Authorization"));
    if (token === null) return problem(c, unauthorized("a bearer token is required"));

    const outcome = await authenticate(token);
    if ("refusal" in outcome) return problem(c, outcome.refusal);

    c.set("principal", outcome.principal);
    await next();
  };

  return {
    requireJwt,

    requireScope: (scope: string): MiddlewareHandler<AuthEnv> => {
      const required = parseText(scope, "scope");

      return async (c, next) => {
        const principal = c.get("principal");
        // A route with the gate and no auth in front of it is a wiring mistake,
        // not an authorization decision: nothing has been proven yet, so the
        // answer is 401 and not 403.
        if (!principal) return problem(c, unauthorized("a bearer token is required"));

        if (!principal.scope.includes(required)) {
          return problem(c, {
            status: 403,
            code: "forbidden",
            // The scope that is missing is guard's own configuration and is safe
            // to name. The scopes the caller does hold are not echoed back.
            detail: `token is missing the ${required} scope`,
          });
        }

        await next();
      };
    },
  };
}

/**
 * The protected header, read before anything else.
 *
 * This runs before any key is fetched: the algorithm and the key id are
 * attacker-controlled, and an `alg: none` or HS256 token must not be able to
 * make guard call identity. It also means a malformed token costs no network.
 */
function decodeHeader(token: string): Header {
  let header: { alg?: unknown; kid?: unknown };
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return { ok: false, refusal: unauthorized("token is malformed") };
  }

  if (header.alg !== ALGORITHM) {
    return { ok: false, refusal: unauthorized(`token algorithm '${String(header.alg)}' is not accepted`) };
  }
  if (typeof header.kid !== "string" || header.kid === "") {
    return { ok: false, refusal: unauthorized("token header names no key") };
  }

  return { ok: true, kid: header.kid };
}

/**
 * jose's failures, as reasons a caller can act on.
 *
 * Only the code and the claim name are used. The message is jose's, and jose's
 * messages quote expected values — an expected issuer is a map of the platform's
 * internals, and an expected audience is this gateway's client id.
 */
function refusalOf(error: unknown): Problem {
  const code = (error as { code?: unknown } | null)?.code;

  if (code === "ERR_JWT_EXPIRED") return unauthorized("token has expired");
  if (code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") return unauthorized("token signature does not verify");
  if (code === "ERR_JWKS_NO_MATCHING_KEY") return unauthorized("token was signed by an unknown key");
  if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
    return unauthorized(`token claim '${String((error as { claim?: unknown }).claim)}' is not valid`);
  }

  return unauthorized("token is not valid");
}

/** The claims a handler is allowed to see, or the reason there are none. */
function principalOf(payload: JWTPayload): Outcome {
  if (typeof payload.sub !== "string" || payload.sub === "") {
    return { refusal: unauthorized("token has no subject") };
  }

  const raw = payload[SCOPE_CLAIM];
  if (raw !== undefined && typeof raw !== "string") {
    return { refusal: unauthorized("token scope claim is not a string") };
  }

  return {
    principal: {
      sub: payload.sub,
      // An absent claim is an empty set, never everything: a scope gate that
      // treated "no scopes" as "all scopes" would be a gate with no gate.
      scope: typeof raw === "string" ? raw.split(/\s+/).filter(Boolean) : [],
      // A non-string `account_id` is ignored rather than rejected: the token is
      // still a valid token, and a rate-limit key is a worse thing to lose than
      // a well-formed claim is to gain.
      accountId: typeof payload.account_id === "string" && payload.account_id !== "" ? payload.account_id : undefined,
      claims: payload,
    },
  };
}

/**
 * The credential, or null. RFC 6750 §2.1: the scheme is case-insensitive, the
 * token is everything after it, and there is exactly one token.
 */
function bearerToken(authorization: string | undefined): string | null {
  if (!authorization) return null;
  return /^bearer +(\S+)$/i.exec(authorization.trim())?.[1] ?? null;
}

function publishes(keys: JWK[], kid: string): boolean {
  return keys.some((key) => key.kid === kid);
}

/**
 * A key set, or not. An endpoint that answers 200 with a login page is the
 * failure this catches, so the shape is checked before anything is imported.
 */
function isKeySet(document: unknown): document is { keys: JWK[] } {
  if (typeof document !== "object" || document === null) return false;
  const { keys } = document as { keys?: unknown };

  return Array.isArray(keys) && keys.length > 0 && keys.every((key) => typeof key === "object" && key !== null);
}

function unauthorized(detail: string): Problem {
  return { status: 401, code: "unauthorized", detail };
}

function unavailable(): Problem {
  return {
    status: 503,
    code: "unavailable",
    // Fixed string: the URL that failed, the status it answered and the parser's
    // complaint are all in the log already.
    detail: "the signing keys could not be retrieved",
  };
}

/**
 * An absolute http(s) URL.
 *
 * Both the issuer and an explicit key-set URL are configuration an operator
 * types, and a typo in either has to be a startup error rather than a 503 on
 * every request.
 */
function parseHttpUrl(value: string, field: string): URL {
  const text = parseText(value, field);

  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new RangeError(`createJwtVerifier: ${field} must be an absolute URL, got ${JSON.stringify(value)}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RangeError(`createJwtVerifier: ${field} must be http(s), got ${JSON.stringify(value)}`);
  }

  return url;
}

/**
 * The issuer, reduced to its origin.
 *
 * No path is allowed, because the fixed JWKS path is appended to it: a base with
 * a path would put the key set somewhere nobody is serving it from. The trailing
 * slash is dropped, because it is what an operator types out of habit and
 * keeping it would join into `https://identity.localhost//.well-known/…`.
 */
function parseIssuer(value: string): string {
  const url = parseHttpUrl(value, "issuer");

  if (url.pathname !== "/" && url.pathname !== "") {
    throw new RangeError(`createJwtVerifier: issuer must be a base URL with no path, got ${JSON.stringify(value)}`);
  }

  return url.origin;
}

function parseText(value: string, field: string): string {
  const text = typeof value === "string" ? value.trim() : "";
  if (text === "") {
    throw new RangeError(`createJwtVerifier: ${field} must be a non-empty string`);
  }
  return text;
}

function assertPositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new RangeError(`createJwtVerifier: ${field} must be an integer >= 1, got ${String(value)}`);
  }
}
