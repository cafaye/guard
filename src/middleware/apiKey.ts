// API keys: a machine credential for an account.
//
// A browser session is a cookie a human got from a sign-in; an API key is a
// string a script holds. Both prove which account is calling, and the gateway
// treats them the same way afterwards — the same `principal` on the context, the
// same scope gate, and the same rate-limit bucket, because they are the same
// caller. What differs is the storage and the revocation story, and both of those
// are decided by the fact that a key is long-lived and handed to something the
// gateway does not control.
//
// The four rules this file exists to hold:
//
//   1. Only the hash is ever stored. A dump of the store, a backup, a log line
//      or a support screenshot must not be a list of working credentials.
//   2. Only a prefix is ever shown. Twelve characters is enough for a human to
//      tell two keys apart and far too little to use one.
//   3. A secret is shown exactly once, at issue. There is no endpoint anywhere
//      that can print it again, because there is nothing left to print.
//   4. Revocation takes effect on the very next request, and a revoked key is
//      not findable at all — `find` is the only lookup, so the revocation
//      decision cannot exist in two places and disagree with itself.
//
// TODO(guard-07): the in-memory store here is per process and is what the tests
// use. A multi-instance deployment needs one shared store behind this same
// `ApiKeyStore`, the way `RateLimitStore` has two. It is deliberately not
// written yet rather than written wrongly: a key issued on one replica and
// invisible on the next one is a credential that fails at random.
import { createHash, randomUUID, randomBytes } from "node:crypto";
import type { Context, MiddlewareHandler } from "hono";
import { problem, type Problem } from "../problem";
import type { AuthEnv, Principal } from "./jwt";

/** What guard hands back when it issues a key. The only time `key` exists. */
export type IssuedApiKey = {
  /** The secret. Shown once and never recoverable afterwards. */
  key: string;
  /** The first twelve characters, for a human to recognise. */
  prefix: string;
  /** The id, so the key can be listed and revoked without the secret. */
  id: string;
};

/** One stored key. Carries no part of the secret. */
export type ApiKeyRecord = {
  id: string;
  accountId: string;
  /** SHA-256 of the secret, hex. The only thing kept of it. */
  hash: string;
  /** The first twelve characters, for display. */
  prefix: string;
  /** What this key may do, in the same vocabulary as a token's `scope`. */
  scopes: string[];
  /** Epoch ms of withdrawal, or 0 while the key is live. */
  revokedAt: number;
};

/** What `issue` is given. The secret is not one of the fields. */
export type ApiKeyRecordInput = Omit<ApiKeyRecord, "revokedAt">;

/**
 * Where keys live.
 *
 * A trait, like `RateLimitStore`, and for the same reason: an in-memory one for
 * tests and a single process, a shared one for a deployment. The one method that
 * matters for security is `find`, and it is the only way to ask — see rule 4 at
 * the top of this file.
 */
export interface ApiKeyStore {
  /** Stores a record under its hash. Idempotent on the hash. */
  issue(record: ApiKeyRecordInput): Promise<void>;
  /** The live record for this hash, or null. Never answers for a revoked key. */
  find(hash: string): Promise<ApiKeyRecord | null>;
  /** Withdraws a key. Absent and already-revoked are both fine. */
  revoke(id: string): Promise<void>;
  /** Every key an account holds, revoked ones included, for display. */
  list(accountId: string): Promise<ApiKeyRecord[]>;
}

export type MemoryApiKeyStoreOptions = {
  /** Clock, injected so a test can age a record without sleeping. */
  now?: () => number;
};

export type MemoryApiKeyStore = ApiKeyStore & {
  /** Records held right now, revoked ones included. v0 introspection. */
  size(): number;
};

/**
 * Keys in this process's memory.
 *
 * SINGLE-INSTANCE ONLY, for the same reason the in-memory rate-limit store is:
 * a key issued on one replica does not exist on the next, so a deployment behind
 * a load balancer authenticates intermittently. See the TODO at the top.
 */
export function memoryApiKeyStore(options: MemoryApiKeyStoreOptions = {}): MemoryApiKeyStore {
  const { now = Date.now } = options;
  const byHash = new Map<string, ApiKeyRecord>();
  const byId = new Map<string, ApiKeyRecord>();
  const byAccount = new Map<string, Set<string>>();

  return {
    async issue(record) {
      // The same secret twice is the same key, not two: a caller must not be
      // able to accumulate aliases for one credential and then have to guess
      // which id to revoke.
      if (byHash.has(record.hash)) return;

      const stored: ApiKeyRecord = { ...record, revokedAt: 0 };
      byHash.set(record.hash, stored);
      byId.set(record.id, stored);
      const held = byAccount.get(record.accountId) ?? new Set<string>();
      held.add(record.id);
      byAccount.set(record.accountId, held);
    },

    async find(hash) {
      const record = byHash.get(hash);

      // Revocation is decided here and nowhere else. Returning the record with a
      // flag would put the decision in the gate as well, and the two would agree
      // right up until someone forgot to check the flag.
      return record !== undefined && record.revokedAt === 0 ? record : null;
    },

    async revoke(id) {
      const record = byId.get(id);
      // The record stays, so an operator can see what was withdrawn and when.
      // Only `find` stops answering for it.
      if (record) record.revokedAt = now();
    },

    async list(accountId) {
      const held = byAccount.get(accountId);
      if (!held) return [];

      return [...held].map((id) => byId.get(id)).filter((record): record is ApiKeyRecord => record !== undefined);
    },

    size() {
      return byId.size;
    },
  };
}

/**
 * A new key: 32 random bytes, base64url, behind a `caf_` prefix.
 *
 * 256 bits of entropy from the platform CSPRNG. The prefix is not secret and
 * exists so a key that turns up in a log or a screenshot is recognisable as a
 * cafaye key and not as something else, and so the shape check below can tell a
 * key from a typo without a database round trip.
 *
 * 43 base64url characters is exactly 32 bytes, which is the reason the format is
 * this length rather than a rounder one.
 */
export function generateApiKey(): { key: string; prefix: string; hash: string } {
  const key = `caf_${randomBytes(32).toString("base64url")}`;

  return { key, prefix: apiKeyPrefixOf(key)!, hash: hashApiKey(key) };
}

/**
 * SHA-256 of a secret, hex.
 *
 * A plain hash, not a password hash, and the difference matters: an API key is
 * 256 bits of CSPRNG output, so there is no dictionary to attack and the value
 * has to be *deterministic* — the whole lookup is "hash what the caller sent and
 * find the record". A bcrypt or argon2 hash cannot be used to look a key up at
 * all, and a salted one cannot either.
 */
export function hashApiKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

/** `caf_` plus 43 base64url characters. */
const KEY_SHAPE = /^caf_[A-Za-z0-9_-]{43}$/;

/** How much of a key is ever shown. Twelve characters: `caf_` and eight more. */
const PREFIX_LENGTH = 12;

/**
 * The displayable part of a key, or null.
 *
 * A value that is not a key has no prefix: `nope` is a typo in a support ticket,
 * not a credential, and rendering `"nop"` back at somebody invites them to try
 * it. Null is the honest answer and the caller decides what to do with it.
 */
export function apiKeyPrefixOf(key: string): string | null {
  if (typeof key !== "string" || !KEY_SHAPE.test(key)) return null;

  return key.slice(0, PREFIX_LENGTH);
}

export type ApiKeyAuthOptions = {
  keys: ApiKeyStore;
  /** Clock, for the same reason the other stores take one. */
  now?: () => number;
};

export type ApiKeyAuth = {
  /** Whether the request is presenting an API key at all. See `./limitKey`. */
  hasKeyScheme: (c: Context) => boolean;
  /** Authenticates a key, or answers 401. Mount after `hasKeyScheme`. */
  authenticate: MiddlewareHandler<AuthEnv>;
  /** Mints a key for an account and stores only its hash. */
  issue: (input: { accountId: string; scopes: string[] }) => Promise<IssuedApiKey>;
};

/**
 * The API-key surface: issue, authenticate, revoke through the store.
 *
 * `authenticate` is a handler rather than a `MiddlewareHandler` on its own
 * because it has to be *conditional*: a request with no key is somebody else's
 * problem, and one that reaches it must already have presented a key. The shape
 * the app mounts is the one in `apiKey.test.ts`:
 *
 *     if (keys.hasKeyScheme(c)) return keys.authenticate(c, next);
 *     return next();
 */
export function createApiKeyAuth(options: ApiKeyAuthOptions): ApiKeyAuth {
  const { keys } = options;
  const now = options.now ?? Date.now;

  async function lookup(c: Context): Promise<{ ok: true; record: ApiKeyRecord } | { ok: false; refusal: Problem }> {
    const secret = apiKeySecret(c);
    if (secret === null) return { ok: false, refusal: unauthorized("the api key is not valid") };

    // A shape check before the lookup, so a typo is not a database read and a
    // caller cannot use response time to tell a real key from a fake one.
    if (!KEY_SHAPE.test(secret)) return { ok: false, refusal: unauthorized("the api key is not valid") };

    let record: ApiKeyRecord | null;
    try {
      record = await keys.find(hashApiKey(secret));
    } catch (error) {
      // The store being down is not the caller's fault, and a 401 would send
      // them to rotate a credential that is fine. The reason goes to the log.
      console.error("guard: could not read the api key store", error);
      return { ok: false, refusal: unavailable() };
    }

    // One refusal for "no such key" and for "withdrawn key". Which of the two it
    // was is the store's business and the caller's business is that it did not
    // work; telling them apart would confirm that a guessed key once existed.
    if (record === null) return { ok: false, refusal: unauthorized("the api key is not valid") };

    return { ok: true, record };
  }

  return {
    hasKeyScheme: hasApiKeyScheme,

    authenticate: async (c, next) => {
      const outcome = await lookup(c);
      if (!outcome.ok) return problem(c, outcome.refusal);

      const { record } = outcome;
      // The same principal a token would set, so there is one scope gate in this
      // repository rather than two that could disagree. `accountId` is the
      // account, which is what the rate limiter and the billing path key on.
      c.set("principal", {
        sub: record.accountId,
        accountId: record.accountId,
        scope: record.scopes,
        claims: { sub: record.accountId, account_id: record.accountId, scope: record.scopes.join(" ") },
      } satisfies Principal);
      c.set("apiKeyId", record.id);

      await next();
    },

    issue: async ({ accountId, scopes }) => {
      const owner = requireText(accountId, "accountId");
      const held = requireScopes(scopes);
      const made = generateApiKey();
      // Minted once and used twice. An `issue` that returned a second id would
      // hand the caller something it cannot revoke, because the id it can revoke
      // is the one the store holds.
      const id = `key_${randomUUID()}`;

      try {
        await keys.issue({ id, accountId: owner, hash: made.hash, prefix: made.prefix, scopes: held });
      } catch (error) {
        // A key whose hash is not stored is a key the caller was told about and
        // cannot use, so this has to be a failure rather than a success with a
        // dangling secret.
        console.error("guard: could not store a newly issued api key", error);
        throw new Error("guard: the api key store rejected a new key");
      }

      return { key: made.key, prefix: made.prefix, id };
    },
  };
}

/**
 * The credential, or null. The same shape RFC 6750 §2.1 gives a bearer token:
 * case-insensitive scheme, one token, nothing after it.
 */
function apiKeySecret(c: Context): string | null {
  const authorization = c.req.header("authorization")?.trim();
  const match = /^apikey +(\S+)$/i.exec(authorization ?? "");

  return match?.[1] ?? null;
}

/** The scheme test, from `./limitKey` — one definition, two callers. */
function hasApiKeyScheme(c: Context): boolean {
  const authorization = c.req.header("authorization")?.trim();

  return typeof authorization === "string" && /^apikey(?:\s|$)/i.test(authorization);
}

function requireText(value: string, field: string): string {
  const text = typeof value === "string" ? value.trim() : "";
  if (text === "") throw new RangeError(`api key ${field} must be a non-empty string`);

  return text;
}

/**
 * Scopes, checked at issue.
 *
 * A scope that is not a scope is a startup-shaped mistake: a key that was
 * issued with a blank scope holds a scope the gate will never match, so the key
 * silently cannot do the thing it was minted for, and the operator finds out
 * from a 403 rather than from a failed issuance. `""` and `" "` are the two ways
 * a template produces one.
 */
function requireScopes(scopes: string[]): string[] {
  if (!Array.isArray(scopes)) throw new RangeError("api key scopes must be an array");

  return scopes.map((scope) => {
    const text = requireText(scope, "scope");
    // A scope is one token: a scope with a space in it can never match the
    // whitespace-split `scope` claim it is compared against.
    if (/\s/.test(text)) throw new RangeError(`api key scope must be a single token, got ${JSON.stringify(scope)}`);

    return text;
  });
}

function unauthorized(detail: string): Problem {
  return { status: 401, code: "unauthorized", detail };
}

function unavailable(): Problem {
  return {
    status: 503,
    code: "unavailable",
    // Fixed string, as everywhere else: the store's host and error are in the log.
    detail: "the api keys could not be retrieved",
  };
}
