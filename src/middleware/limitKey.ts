// Which bucket a request belongs to.
//
// This is the file the whole limiter rests on, because a rate limiter is only as
// good as the identity of the thing it is counting. The key is derived in one
// order and one order only:
//
//   1. the account id from the *verified* principal  ->  `account:<id>`
//   2. the id of an API key the store authenticated   ->  `apikey:<id>`
//   3. the client address, when the deployment says it can be trusted
//                                                         ->  `ip:<address>`
//   4. nothing at all                                    ->  `ip:unknown`
//
// What is never a key:
//
//   * a header value. `X-Account-Id` is chosen by the caller, and a limiter
//     keyed on it is not a limiter: it is a way for every caller to mint a fresh
//     allowance per request, which is a self-DoS with extra steps.
//   * an unverified token. Nothing reaches this module before the JWT verifier
//     or the API-key gate has run, so `principal` is a fact and not a claim. A
//     token that fails verification is answered 401 by the gate ahead of the
//     limiter and never becomes a key at all — see `rateLimit.test.ts`.
//
// The prefixes are load-bearing in a second way: they are the counter key, so
// an account id that collides with an address can never share a bucket with it.
import type { Context } from "hono";
import { assertNonNegativeInteger } from "./assert";
import type { AuthEnv, Principal } from "./jwt";

/** What is known about the caller by the time the limiter reads the context. */
export type KeySource = {
  /** The account id from the verified principal, or null when there is none. */
  accountId: string | null;
  /** The id of the API key that authenticated, or null. */
  apiKeyId: string | null;
  /** The client address, or "" when it could not be established. */
  address: string;
};

/** The bucket name. Two callers share a bucket exactly when this is equal. */
export function rateLimitKey({ accountId, apiKeyId, address }: KeySource): string {
  if (present(accountId)) return `account:${accountId}`;
  if (present(apiKeyId)) return `apikey:${apiKeyId}`;
  if (present(address)) return `ip:${address}`;

  // A named unknown rather than a blank: a blank key is a key every unresolved
  // caller shares, which is correct — and it is also a key that reads like a bug
  // in a log line six months from now.
  return "ip:unknown";
}

/**
 * The account a verified principal belongs to, or null.
 *
 * `account_id` is the claim identity issues for the account a request acts on,
 * which is not always the subject: a user acting inside a workspace has a `sub`
 * of their own and an `account_id` of the workspace. When identity issues no
 * `account_id`, the subject stands in — the user *is* the account, and refusing
 * to fall back would mean a token that is perfectly valid gets no limiter at all,
 * which is the one outcome worse than sharing a bucket.
 */
export function accountIdOf(principal: Principal | undefined): string | null {
  if (!principal) return null;

  const claim = principal.claims?.account_id;

  return present(principal.accountId) ? principal.accountId : presentString(claim) ? claim : present(principal.sub) ? principal.sub : null;
}

/** The credential from the request context, for a middleware to key on. */
export function keySourceOf(c: Context<AuthEnv>, trustedProxies: number): KeySource {
  return {
    // Typed as present, absent at runtime for anonymous traffic: `accountIdOf`
    // takes undefined, and the only routes that reach a handler are behind a gate
    // that either set a principal or answered 401.
    accountId: accountIdOf(c.get("principal")),
    apiKeyId: c.get("apiKeyId") ?? null,
    address: clientIp(c, trustedProxies),
  };
}

export type KeyVariables = AuthEnv["Variables"];

/** What stands in for an address guard could not establish. */
const UNKNOWN = "unknown";

/**
 * The client address, and how much of `X-Forwarded-For` is believed.
 *
 * `X-Forwarded-For` is a list the *caller* can write, and the caller can write
 * as much of it as they like. So the number that matters is how many proxies the
 * operator says stand in front of guard, and the entry is read from the RIGHT of
 * the chain: everything to the left of the trusted run is whatever the caller
 * felt like sending. `TRUSTED_PROXIES=2` means two proxies appended to the
 * header, and the address is the second entry from the end — the last one that
 * arrived from something the operator vouches for.
 *
 * With `trustedProxies` at zero the header is not read at all and the answer is
 * the socket peer. That is the honest default: a guard directly exposed to the
 * internet has no forwarding chain to believe, and believing one anyway is how a
 * caller walks around the limiter by sending a new address per request.
 *
 * A chain shorter than the trusted run falls back to the peer for the same
 * reason: there is no entry the operator vouched for, so the only address left is
 * the one the kernel gave us, and a bucket that is too broad is the direction to
 * be wrong in.
 */
export function clientIp(c: Context, trustedProxies: number): string {
  assertNonNegativeInteger(trustedProxies, "trustedProxies");
  if (trustedProxies === 0) return peerAddress(c);

  const chain = forwardedChain(c);
  // index `trustedProxies` from the right is index `length - trustedProxies` from
  // the left, and a negative index means the chain is shorter than the run.
  const claimed = chain[chain.length - trustedProxies];

  return addressOf(claimed) ?? peerAddress(c);
}

/**
 * `X-Forwarded-For`, split.
 *
 * Positions are preserved, blanks included: entry *n* is hop *n*, and a proxy
 * that appended nothing leaves a hole rather than shortening the chain. A hole is
 * read as "no address at this hop" and never becomes a bucket of its own.
 */
function forwardedChain(c: Context): string[] {
  const header = c.req.header("x-forwarded-for");
  if (!header) return [];

  return header.split(",").map((entry) => entry.trim());
}

/**
 * The socket peer, when the server exposes it.
 *
 * `c.env` is the Bun `Server` when guard is served by `Bun.serve` and undefined
 * under `app.request()`, which is why a test sees `unknown` here rather than an
 * address: there is no socket, and inventing one would be a fabricated identity.
 */
function peerAddress(c: Context): string {
  const server = c.env as { requestIP?: (request: Request) => { address: string } | null } | undefined;
  const address = server?.requestIP?.(c.req.raw)?.address;

  return addressOf(address) ?? UNKNOWN;
}

/**
 * An address, or null.
 *
 * Entries are checked rather than passed through: a bucket name ends up in a
 * Redis key, and a header a caller chose must not be able to put a newline, a
 * space or a brace in one. Only something shaped like an IP literal is accepted,
 * with an optional port and IPv6 brackets stripped, and `unknown` is refused so
 * it cannot be confused with the placeholder that means the same thing.
 */
function addressOf(entry: string | undefined): string | null {
  if (typeof entry !== "string") return null;

  const bare = stripPort(entry.trim().toLowerCase());
  if (bare === "" || bare === UNKNOWN) return null;

  return IP_LITERAL.test(bare) ? bare : null;
}

/** `[::1]:443` and `203.0.113.4:443` both reduce to the address. */
function stripPort(value: string): string {
  const bracketed = /^\[([^\]]+)](?::\d+)?$/.exec(value);
  if (bracketed) return bracketed[1] ?? "";

  // A bare IPv6 literal has colons and no port, so a single trailing `:digits`
  // is the only port that can be peeled off.
  return /:\d+$/.test(value) && (value.match(/:/g)?.length ?? 0) === 1 ? value.slice(0, value.lastIndexOf(":")) : value;
}

const IP_LITERAL = /^[0-9a-f:.%]+$/;

/** The API key credential scheme, case-insensitive as HTTP auth schemes are. */
const API_KEY_SCHEME = /^apikey(?:\s|$)/i;

/**
 * Whether this request is carrying an API key at all.
 *
 * Deliberately about the scheme and not the token: `Authorization: ApiKey` with
 * nothing after it is a request that tried to authenticate with a key, and it
 * has to be answered 401 by the key gate rather than quietly falling through to
 * the token gate as an anonymous request. A `Bearer` token is somebody else's
 * credential and is left alone.
 */
export function hasApiKeyScheme(c: Context): boolean {
  const authorization = c.req.header("authorization")?.trim();

  return typeof authorization === "string" && API_KEY_SCHEME.test(authorization);
}

function present(value: string | null | undefined): value is string {
  return typeof value === "string" && value !== "";
}

function presentString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}
