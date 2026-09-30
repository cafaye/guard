// Which allowance a route draws on, in configuration rather than in code.
//
// A gateway that gives one number to every route cannot be strict where
// strictness is what stops an attack and generous where generosity is what a
// client needs. This file is the table: one entry per policy, the prefix that
// claims it, and the `policy` name that ends up in `RateLimit-Policy` so a
// caller can see which budget it is spending.
//
// The `policy` name is not decoration. It is half of the counter key, so two
// entries that share a name share an allowance — which is why `/auth/login` and
// `/auth/register` are separate policies rather than two numbers under
// `guard-auth`: a caller who burns the registration budget must not be able to
// lock out every legitimate sign-up from that address by brute-forcing logins
// under one shared bucket. `limits.test.ts` asserts one rule per shipped entry.
import { assertPositiveInteger, assertStructuredKey } from "./assert";

/** One allowance: how many requests, over how long, under what name. */
export type Limit = {
  /** Requests per window. A whole number >= 1. */
  limit: number;
  /** Window length in milliseconds. A whole number >= 1. */
  windowMs: number;
  /**
   * The name in `RateLimit-Policy` and `RateLimit`, and half the counter key.
   * Constrained to a structured-field key (RFC 9651 §3.1.1.3) because it is
   * written into a response header verbatim.
   */
  policy: string;
};

export type LimitTable = {
  /** What a path no entry claims gets. Always consulted, never optional. */
  default: Limit;
  /**
   * Path prefix -> allowance. Longest matching prefix wins. Required, and `{}` is
   * a valid value: a gateway with one allowance everywhere writes an empty
   * object rather than a missing field, so a table that has been half-read is a
   * type error instead of a silent "everything falls back to the default".
   */
  routes: Record<string, Limit>;
};

/** One minute, the unit every shipped entry is expressed in. */
const MINUTE_MS = 60_000;

/**
 * What guard ships with.
 *
 * The numbers are a starting point, not a measurement: nothing in this
 * repository has watched a real caller. They are chosen so the ordering is
 * defensible on its face — a password attempt is the scarcest thing a public
 * edge serves, an authenticated API call is not — and an operator with a real
 * traffic shape replaces this table with their own through `RATE_LIMIT_TABLE`.
 */
export const DEFAULT_LIMIT_TABLE: LimitTable = {
  default: { limit: 600, windowMs: MINUTE_MS, policy: "guard-api" },
  routes: {
    // Auth-adjacent, and stricter than the API default: a login is guessable
    // work, and the per-minute allowance is what makes guessing slow.
    "/auth/": { limit: 60, windowMs: MINUTE_MS, policy: "guard-auth" },
    "/auth/login": { limit: 10, windowMs: MINUTE_MS, policy: "guard-auth-login" },
    "/auth/register": { limit: 5, windowMs: MINUTE_MS, policy: "guard-auth-register" },
    "/auth/logout": { limit: 30, windowMs: MINUTE_MS, policy: "guard-auth-logout" },
    "/v1/": { limit: 600, windowMs: MINUTE_MS, policy: "guard-api" },
    // Minting and revoking credentials is a write on the security surface, so
    // it gets its own budget rather than the general API's.
    "/v1/api-keys": { limit: 60, windowMs: MINUTE_MS, policy: "guard-api-keys" },
  },
};

/**
 * A table, validated.
 *
 * Every number and every policy name is checked here, at construction, because a
 * limit of `0` or a policy name that cannot be serialised into a header is a
 * startup failure and not a surprise on the first request of the week. Nothing
 * validates on the request path: `resolveLimit` is called on every request and
 * must stay a map lookup.
 */
export function limitTable(table: LimitTable): LimitTable {
  const checked: LimitTable = {
    default: checkLimit(table.default, "default"),
    routes: Object.fromEntries(
      Object.entries(table.routes ?? {}).map(([prefix, entry]) => [checkPrefix(prefix), checkLimit(entry, prefix)]),
    ),
  };

  return checked;
}
function checkLimit(limit: Limit, field: string): Limit {
  assertPositiveInteger(limit?.limit, `${field}.limit`);
  assertPositiveInteger(limit?.windowMs, `${field}.windowMs`);
  assertStructuredKey(limit?.policy, `${field}.policy`);

  return { limit: limit.limit, windowMs: limit.windowMs, policy: limit.policy };
}

/**
 * A prefix is a path, never a pattern.
 *
 * No `*` and no `?`: a glob is a second matching language to get wrong, and the
 * only thing a route needs is "everything under here". The trailing slash is
 * left alone because it is meaningful to the matcher.
 */
function checkPrefix(prefix: string): string {
  if (typeof prefix !== "string" || !prefix.startsWith("/") || prefix.includes("*") || prefix.includes("?")) {
    throw new RangeError(`limitTable: route prefixes must be absolute paths without globs, got ${JSON.stringify(prefix)}`);
  }
  return prefix;
}

/**
 * The allowance for one request path.
 *
 * Longest matching prefix wins, so `/v1/api-keys` beats `/v1/` and the order the
 * entries were written in does not matter — a table that resolved in insertion
 * order would quietly change meaning the first time someone moved a line.
 *
 * A prefix matches on a path-segment boundary. `/v1/` claims `/v1/me` and not
 * `/v1alpha/`, so a new top-level route cannot inherit an allowance by sharing a
 * name with an old one. Anything unclaimed gets `default`, which is why `default`
 * is a required field and not a convenience.
 */
export function resolveLimit(table: LimitTable, path: string): Limit {
  const target = pathname(path);
  let best: Limit | undefined;
  let bestLength = -1;

  for (const [prefix, limit] of Object.entries(table.routes)) {
    if (prefix.length <= bestLength || !claims(prefix, target)) continue;

    best = limit;
    bestLength = prefix.length;
  }

  return best ?? table.default;
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
