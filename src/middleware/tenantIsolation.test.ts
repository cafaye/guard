// Account A must not be able to reach account B's state.
//
// ## What this file is for
//
// guard is the only door into a cafaye deployment, so a tenant boundary here is
// a boundary in front of everything behind it. This file writes the negative
// case for every account-scoped entry point: account A asks for something that
// belongs to account B, and the answer must be **absence** — `null`, `[]`,
// `false`, a 401, an untouched counter.
//
// ## Absence, never 403
//
// The refusal must be indistinguishable from the answer for a thing that does
// not exist. A `403` says "that is real and it is not yours", which is an
// enumeration oracle: a caller walking ids learns which exist and who owns them
// without reading a single row of them. So every negative assertion in this file
// is `null`, `[]`, `false` or `401`, and a `403` where one of those belongs is a
// **finding**, not a near miss.
//
// The two `403`s guard does write are capability failures — a token without
// `invoices.write`, and a request that is not same-origin — and both are
// correct: there is no resource being named in either case, so there is no
// existence to leak, and the caller already knows the fact being reported about
// them. `a_403_is_only_ever_a_capability_or_an_origin` holds that line.
//
// ## The two defects this file found
//
// Both are in `memoryApiKeyStore`, both are at the store rather than the wire,
// and neither is reachable through a route today — guard has no endpoint that
// issues or revokes a key. They are load-bearing anyway, because the store is
// the seam `TODO(guard-07)` moves to Redis and the trait is what the future
// `/v1/api-keys` route will call. A store whose scoping is wrong is a store
// whose Redis implementation will be written from a signature that does not
// mention the account, and the first route that calls it is the day it becomes
// exploitable rather than theoretical.
//
//   1. `revoke(id)` took no account at all, so any caller who learned another
//      account's key id could withdraw it — a cross-tenant **write**. It now
//      takes the account and refuses to touch a record that is not that
//      account's.
//
//   2. `list(accountId)` walked an id set and looked each id up in a map keyed
//      by id alone, so two accounts holding the same id made one account's
//      listing return the *other* account's record — hash and prefix included —
//      which is a cross-tenant **read**. It now filters on the record's own
//      `accountId` rather than trusting the id set.
//
// Both are asserted below in both directions: A cannot reach B, and B's state is
// provably unchanged afterwards. A test that only asserted "A got nothing" would
// pass against an implementation that deleted B's row on the way past.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Hono } from "hono";
import { createApp } from "../index";
import {
  createApiKeyAuth,
  hashApiKey,
  memoryApiKeyStore,
  type ApiKeyRecordInput,
  type ApiKeyStore,
  type IssuedApiKey,
} from "./apiKey";
import { createJwtVerifier, type AuthEnv, type Principal } from "./jwt";
import { rateLimit } from "./rateLimit";
import { memoryRateLimitStore } from "./rateLimitStore";
import { GCRA_LUA, redisRateLimitStore, type RedisCommands } from "./rateLimitRedis";
import { keySourceOf, rateLimitKey } from "./limitKey";
import { signToken, startJwksServer, testKey, tamperPayload, type JwksServer, type TestKey } from "../../test/jwksServer";

/**
 * A stand-in for Redis that runs `GCRA_LUA`'s own algorithm, line for line.
 *
 * Duplicated from `rateLimitRedis.test.ts` rather than imported, and that is a
 * deliberate cost: the alternative is this file reaching into another test file
 * for an export that file does not have, and a shared helper for two
 * transcriptions of one Lua body would be a third thing to keep honest. What
 * this file needs from Redis is only that two accounts' buckets are separate
 * keys, so the algorithm is a means; the script *itself* is executed against a
 * real server by `rateLimitRedisLive.test.ts`, which is the tier that can
 * actually be wrong about it.
 */
function fakeRedis(): RedisCommands {
  const keys = new Map<string, number>();

  return {
    async eval(script, keysIn, args) {
      if (script !== GCRA_LUA) throw new Error("unexpected script");
      if (keysIn.length !== 1) throw new Error("expected exactly one key");

      const key = keysIn[0] ?? "";
      const tat = keys.get(key) ?? 0;
      const limit = Number(args[0]);
      const windowMs = Number(args[1]);
      const now = Number(args[2]);
      const interval = windowMs / limit;
      const next = Math.max(now, tat) + interval;
      if (next - now > windowMs) return [0, tat, next - windowMs, 0];
      keys.set(key, next);
      return [1, next, next - interval - windowMs, Math.max(0, limit - Math.ceil((next - now) / interval))];
    },
    async ping() {
      return true;
    },
  };
}

/** What `bucket()` in `./rateLimit` does to an identity before it reaches Redis. */
function digestOf(identity: string): string {
  return createHash("sha256").update(identity, "utf8").digest("hex").slice(0, 32);
}

/**
 * Two accounts that are visibly different in every field that could be echoed,
 * so a leak of one into the other's answer is a string match and not a shape
 * comparison. UUIDs rather than `acc-a`/`acc-b` because a short id is a prefix
 * of nothing here but a digest of one is, and a test that passes on
 * `acc-a`/`acc-b` may be passing on the prefix.
 */
const A = "aaaaaaaa-0000-4000-8000-000000000001";
const B = "bbbbbbbb-0000-4000-8000-000000000002";
/** An account that has issued nothing and holds nothing. */
const NOBODY = "cccccccc-0000-4000-8000-000000000003";

const CLIENT_ID = "guard-test";
const WINDOW_MS = 60_000;

let identity: JwksServer;
let signingKey: TestKey;

beforeAll(async () => {
  signingKey = await testKey("tenant-isolation-1");
  identity = await startJwksServer(signingKey);
});

afterAll(() => identity.stop());

const tokenFor = (accountId: string, scope = "invoices.read"): Promise<string> =>
  signToken(signingKey, {
    iss: identity.issuer,
    aud: CLIENT_ID,
    sub: `user-of-${accountId}`,
    account_id: accountId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300,
    scope,
  });

const asBearer = (token: string): RequestInit => ({ headers: { Authorization: `Bearer ${token}` } });

/** The gateway, with both credential gates and the limiter mounted as shipped. */
function gateway(keys?: ApiKeyStore) {
  return createApp({
    jwt: { issuer: identity.issuer, audience: CLIENT_ID },
    rateLimit: { limits: { default: { limit: 600, windowMs: WINDOW_MS, policy: "guard-api" }, routes: {} } },
    ...(keys === undefined ? {} : { apiKeys: { keys } }),
  });
}

// ---------------------------------------------------------------------------
// read: GET /v1/me
// ---------------------------------------------------------------------------

describe("read — GET /v1/me answers with the caller's own account and no other", () => {
  test("A's own response names A", async () => {
    const res = await gateway().request("/v1/me", asBearer(await tokenFor(A)));

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ sub: `user-of-${A}`, accountId: A });
  });

  test("A's response contains no byte of B's account, however A asks for it", async () => {
    // The headers are the part a caller controls freely, so each one is a
    // separate attempt to name somebody else. `accountId` and the `claims` echo
    // are both checked because the route returns the whole principal.
    const attempts: Record<string, string> = {
      "x-account-id": B,
      "x-guard-account": B,
      "x-guard-account-id": B,
      "x-forwarded-account": B,
      account: B,
      "x-tenant": B,
      "x-workspace-id": B,
    };

    for (const [header, value] of Object.entries(attempts)) {
      const res = await gateway().request("/v1/me", {
        headers: { Authorization: `Bearer ${await tokenFor(A)}`, [header]: value },
      });
      const body = await res.text();

      expect(res.status).toBe(200);
      expect(body).not.toContain(B);
      // And the caller still gets itself, so this is not a pass because the
      // route answered empty for everyone.
      expect(body).toContain(A);
    }
  });

  test("a token whose account_id was edited after signing is refused, not honoured", async () => {
    // The signature covers the payload, so a rewritten `account_id` is a token
    // that does not verify. This is the assertion that matters most on a route
    // whose whole output *is* the caller's account: the 401 has to come from
    // verification rather than from the route declining to look.
    const forged = tamperPayload(await tokenFor(A), {
      iss: identity.issuer,
      aud: CLIENT_ID,
      sub: `user-of-${A}`,
      account_id: B,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      scope: "invoices.read",
    });

    const res = await gateway().request("/v1/me", asBearer(forged));

    expect(res.status).toBe(401);
    expect(await res.text()).not.toContain(B);
  });

  test("a forged token is refused the same way as one that was never issued", async () => {
    // The two rejections are for genuinely different reasons — a rewritten
    // payload fails its signature, a fabricated one names no key — so the
    // *detail* is allowed to differ and saying so is the point: a refusal that
    // named the tenant would be the leak, and the reason for refusing a token is
    // not. What has to match is the status and the code, and what must not appear
    // in either body is B.
    const forged = tamperPayload(await tokenFor(A), {
      iss: identity.issuer,
      aud: CLIENT_ID,
      sub: `user-of-${A}`,
      account_id: B,
      exp: Math.floor(Date.now() / 1000) + 300,
      scope: "invoices.read",
    });
    const nonsense = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJub2JvZHkub2JqZWN0In0.not-a-signature";

    const fromForgery = await gateway().request("/v1/me", asBearer(forged));
    const fromNothing = await gateway().request("/v1/me", asBearer(nonsense));

    expect(fromForgery.status).toBe(fromNothing.status);
    const codeOf = async (res: Response): Promise<unknown> => ((await res.json()) as { code: string }).code;
    expect(await codeOf(fromForgery)).toBe(await codeOf(fromNothing));
    expect(await fromForgery.clone().text()).not.toContain(B);
    expect(await fromNothing.clone().text()).not.toContain(B);
  });

  test("a cross-tenant read is a 401 and never a 403", async () => {
    const res = await gateway().request("/v1/me", asBearer(tamperPayload(await tokenFor(A), { account_id: B })));

    expect(res.status).not.toBe(403);
  });
});

// ---------------------------------------------------------------------------
// list: ApiKeyStore.list(accountId)
// ---------------------------------------------------------------------------

describe("list — an account sees its own keys and only its own", () => {
  /** Two accounts, one key each, so every listing has something to be right about. */
  async function twoAccounts() {
    const store = memoryApiKeyStore();
    const auth = createApiKeyAuth({ keys: store });
    const mine = await auth.issue({ accountId: A, scopes: ["invoices.read"] });
    const theirs = await auth.issue({ accountId: B, scopes: ["invoices.write"] });
    return { store, auth, mine, theirs };
  }

  test("A's listing holds A's key and never mentions B's", async () => {
    const { store, theirs } = await twoAccounts();

    const listed = await store.list(A);

    expect(listed.map((record) => record.id)).toEqual([expect.any(String)]);
    expect(listed.every((record) => record.accountId === A)).toBe(true);
    const rendered = JSON.stringify(listed);
    expect(rendered).not.toContain(theirs.prefix);
    expect(rendered).not.toContain(theirs.key);
  });

  test("an account that has issued nothing gets an empty list, not someone else's", async () => {
    const { store } = await twoAccounts();

    expect(await store.list(NOBODY)).toEqual([]);
  });

  test("two accounts holding the same key id do not bleed into each other's listing", async () => {
    // The defect this caught. `byId` was keyed by id alone, so the second
    // `issue` overwrote the first and A's listing resolved A's id to *B's*
    // record — B's hash, B's prefix, B's scopes, under A's own query. Not
    // reachable through `createApiKeyAuth.issue`, which mints a randomUUID, and
    // reachable the moment a shared store trusts a caller-chosen id.
    //
    // Records are written straight to the store rather than through the issuer,
    // deliberately: `issue` is idempotent on the *hash*, so a fixture built by
    // calling `createApiKeyAuth.issue` and then re-issuing under a colliding id
    // is silently a no-op — the second `issue` returns early, the collision never
    // happens, and the test passes against the broken store for the wrong reason.
    // That is what the first draft of this case did, and it passed with the
    // filter removed.
    const store = memoryApiKeyStore();
    const sharedId = "key_11111111-1111-4111-8111-111111111111";
    await store.issue({ id: sharedId, accountId: A, hash: hashApiKey("caf_" + "a".repeat(43)), prefix: "caf_aaaaaaaa", scopes: [] });
    await store.issue({ id: sharedId, accountId: B, hash: hashApiKey("caf_" + "b".repeat(43)), prefix: "caf_bbbbbbbb", scopes: [] });

    const listed = await store.list(A);

    expect(listed.every((entry) => entry.accountId === A)).toBe(true);
    // B's prefix and hash must be absent — the leak was not that A saw *a*
    // record, it was that the record was about somebody else, credential
    // material included.
    const rendered = JSON.stringify(listed);
    expect(rendered).not.toContain("caf_bbbbbbbb");
    expect(rendered).not.toContain(hashApiKey("caf_" + "b".repeat(43)));
    // And the pre-condition is asserted, because a fixture that failed to
    // collide would make both assertions above vacuously true.
    expect(store.size()).toBe(1);
  });

  test("a listing is a 401 for a caller with no credential, and no route reaches the store", async () => {
    // `list` is not on a route, so there is no wire form of this yet. What is
    // assertable is the half that is true today: the app exposes no listing
    // surface at all, so there is no endpoint for one account to ask about
    // another's keys through.
    const app = gateway(memoryApiKeyStore());

    expect(app.routes.map((route) => `${route.method} ${route.path}`)).not.toContain("GET /v1/api-keys");
    expect((await app.request("/v1/api-keys")).status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// update: ApiKeyStore.revoke(accountId, id)
// ---------------------------------------------------------------------------

describe("update — one account cannot withdraw another account's key", () => {
  async function twoAccounts() {
    const store = memoryApiKeyStore();
    const auth = createApiKeyAuth({ keys: store });
    const mine = await auth.issue({ accountId: A, scopes: ["invoices.read"] });
    const theirs = await auth.issue({ accountId: B, scopes: ["invoices.write"] });
    return { store, auth, mine, theirs };
  }

  test("A naming B's key id changes nothing, and B's key still works", async () => {
    const { store, theirs } = await twoAccounts();

    await store.revoke(A, theirs.id);

    // Absence, asserted as the credential still authenticating: a cross-tenant
    // revoke that returned "not found" *and* revoked the key would satisfy a
    // weaker version of this test.
    expect(await store.find(hashApiKey(theirs.key))).not.toBeNull();
  });

  test("B's record is not even marked revoked by A's attempt", async () => {
    // A revocation that missed its scoping and then reported success leaves
    // `revokedAt` behind, which is the trace an operator reads. So this asserts
    // the record's own state rather than the lookup.
    const { store, theirs } = await twoAccounts();

    await store.revoke(A, theirs.id);

    const [record] = await store.list(B);
    expect(record?.id).toBe(theirs.id);
    expect(record?.revokedAt).toBe(0);
  });

  test("A cannot revoke B's key by guessing the id either", async () => {
    const { store, theirs } = await twoAccounts();

    for (const guessed of [theirs.id, "key-1", "key_00000000-0000-4000-8000-000000000000", ""]) {
      await store.revoke(A, guessed);
    }

    expect(await store.find(hashApiKey(theirs.key))).not.toBeNull();
  });

  test("revoking another account's key is indistinguishable from revoking nothing", async () => {
    // Both are no-ops with no error and no return value, and this asserts that
    // `revoke` refuses by *not acting* rather than by throwing — a throw here
    // would be a "that key is not yours" oracle one layer below the wire.
    const { store, theirs } = await twoAccounts();

    await store.revoke(A, theirs.id);
    await store.revoke(NOBODY, "key-that-was-never-issued");

    expect(await store.find(hashApiKey(theirs.key))).not.toBeNull();
  });

  test("an account can still revoke its own key, and the next request is 401", async () => {
    const { store, mine } = await twoAccounts();
    const keys = store;
    const app = gateway(keys);
    const headers = { authorization: `ApiKey ${mine.key}` };

    expect((await app.request("/v1/me", { headers })).status).toBe(200);

    await store.revoke(A, mine.id);

    const refused = await app.request("/v1/me", { headers });
    expect(refused.status).toBe(401);
    // And the absence is the *same* absence a key that was never issued gets,
    // so a caller cannot use the difference to learn that this one once existed.
    // Two shapes of "no": a well-formed secret nobody issued, and a well-formed
    // secret whose record was withdrawn.
    const neverIssued = await createApiKeyAuth({ keys }).issue({ accountId: NOBODY, scopes: [] });
    await keys.revoke(NOBODY, neverIssued.id);
    const withdrawn = await app.request("/v1/me", {
      headers: { authorization: `ApiKey ${neverIssued.key}` },
    });
    const unknown = await app.request("/v1/me", {
      headers: { authorization: `ApiKey caf_${"A".repeat(43)}` },
    });

    expect(refused.status).toBe(withdrawn.status);
    expect(withdrawn.status).toBe(unknown.status);
    // The bodies agree too, bar the per-response trace id: a withdrawal that
    // said "revoked" beside an unknown that said "invalid" would confirm that a
    // guessed key once existed, which is the enumeration this rule exists to stop.
    const detailOf = async (res: { json(): Promise<unknown> }): Promise<unknown> => {
      const { trace_id: _trace, ...rest } = (await res.json()) as Record<string, unknown>;
      return rest;
    };
    expect(await detailOf(refused.clone())).toEqual(await detailOf(withdrawn));
    expect(await detailOf(refused.clone())).toEqual(await detailOf(unknown));
    expect(await refused.text()).not.toContain(mine.key);
  });
});

// ---------------------------------------------------------------------------
// read/list/update/delete over the API-key gate
// ---------------------------------------------------------------------------

describe("the API-key gate authenticates as the record's account, never a named one", () => {
  test("a key issued to B authenticates as B even when the request names A", async () => {
    const store = memoryApiKeyStore();
    const auth = createApiKeyAuth({ keys: store });
    const theirs = await auth.issue({ accountId: B, scopes: ["invoices.read"] });
    const app = gateway(store);

    const res = await app.request("/v1/me", {
      headers: {
        authorization: `ApiKey ${theirs.key}`,
        "x-account-id": A,
        "account": A,
        "x-guard-account": A,
      },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { accountId: string };
    expect(body.accountId).toBe(B);
  });

  test("one account's key draws on its own bucket, and A exhausting his does not touch B's", async () => {
    const store = memoryApiKeyStore();
    const auth = createApiKeyAuth({ keys: store });
    const mine = await auth.issue({ accountId: A, scopes: [] });
    const theirs = await auth.issue({ accountId: B, scopes: [] });
    // limit 1 per account: the second request each account makes is the one
    // that would be refused if the buckets were shared.
    const app = createApp({
      jwt: { issuer: identity.issuer, audience: CLIENT_ID },
      apiKeys: { keys: store },
      rateLimit: { limits: { default: { limit: 1, windowMs: WINDOW_MS, policy: "guard-api" }, routes: {} } },
    });
    const asA = () => app.request("/v1/me", { headers: { authorization: `ApiKey ${mine.key}` } });
    const asB = () => app.request("/v1/me", { headers: { authorization: `ApiKey ${theirs.key}` } });

    expect((await asA()).status).toBe(200);
    expect((await asA()).status).toBe(429);

    // B's allowance is untouched: not his bucket, so A's spending says nothing
    // about it. This is the cross-tenant direction that matters — the one where
    // a shared bucket is a denial of service one account inflicts on another.
    expect((await asB()).status).toBe(200);
    expect((await asB()).status).toBe(429);
  });

  test("a key's scopes are its own, and one account's key does not widen another's", async () => {
    const store = memoryApiKeyStore();
    const auth = createApiKeyAuth({ keys: store });
    const narrow = await auth.issue({ accountId: A, scopes: ["invoices.read"] });
    const wide = await auth.issue({ accountId: B, scopes: ["invoices.read", "invoices.write"] });
    const jwt = createJwtVerifier({ issuer: identity.issuer, audience: CLIENT_ID });
    const app = new Hono<AuthEnv>();
    app.use("*", async (c, next) => {
      if (auth.hasKeyScheme(c)) return auth.authenticate(c, next);
      return next();
    });
    app.get("/", jwt.requireScope("invoices.write"), (c) => c.json({ ok: true }));

    const narrowRes = await app.request("/", { headers: { authorization: `ApiKey ${narrow.key}` } });
    const wideRes = await app.request("/", { headers: { authorization: `ApiKey ${wide.key}` } });

    // The narrow key is refused and the wide one is not, so scopes are per
    // record. A 403 here is correct — see the rule at the top of this file: it
    // is a capability failure and no resource is being named.
    expect(narrowRes.status).toBe(403);
    expect(wideRes.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// the counter store, keyed by account
// ---------------------------------------------------------------------------

describe("rate-limit state keyed by account", () => {
  /** The limiter over a chosen store, with the account the way the gate sets it. */
  function limited(store: Parameters<typeof rateLimit>[0]["store"], accountId: string, limit = 3) {
    const app = new Hono<AuthEnv>();
    const limiter = rateLimit({
      limit,
      windowMs: WINDOW_MS,
      store,
      trustedProxies: 0,
      now: () => 0,
      policy: () => "guard-api",
    });
    app.use("*", async (c, next) => {
      const principal: Principal = {
        sub: `user-of-${accountId}`,
        accountId,
        scope: [],
        claims: { sub: `user-of-${accountId}`, account_id: accountId },
      };
      c.set("principal", principal);
      return limiter(c, next);
    });
    app.get("/", (c) => c.json({ ok: true }));
    return app;
  }

  test("A exhausting his allowance leaves B's untouched and unreadable", async () => {
    const store = memoryRateLimitStore();
    const asA = limited(store, A);
    const asB = limited(store, B);

    for (let i = 0; i < 3; i++) expect((await asA.request("/")).status).toBe(200);
    const aRefused = await asA.request("/");

    // B is not throttled by anything A did — the denial-of-service direction.
    expect((await asB.request("/")).status).toBe(200);

    // And B's headers do not report A's debt, which is the read direction: a
    // `RateLimit-Remaining` of 0 in B's response would tell B that somebody
    // else is being throttled, and a shared bucket is exactly how that leaks.
    const bFirst = await asB.request("/");
    expect(Number(bFirst.headers.get("RateLimit-Remaining"))).toBeGreaterThan(0);
    expect(Number(aRefused.headers.get("RateLimit-Remaining"))).toBe(0);
  });

  test("the same holds when the buckets live in Redis rather than in memory", async () => {
    // The production store for a multi-replica deployment, over the same key
    // derivation. The *arithmetic* of the Redis path is held by
    // `rateLimitParity.test.ts` and executed by the live tier; what is isolated
    // here is that a bucket is addressed by one account and no other, and that
    // property is in the key the two stores derive identically.
    const store = redisRateLimitStore({ commands: fakeRedis() });
    const asA = limited(store, A);
    const asB = limited(store, B);

    for (let i = 0; i < 3; i++) expect((await asA.request("/")).status).toBe(200);
    const aRefused = await asA.request("/");
    const bFirst = await asB.request("/");

    expect(aRefused.status).toBe(429);
    expect(bFirst.status).toBe(200);
    expect(Number(bFirst.headers.get("RateLimit-Remaining"))).toBeGreaterThan(0);
  });

  test("two accounts never share a bucket, and the key names exactly one of them", async () => {
    expect(rateLimitKey({ accountId: A, apiKeyId: null, address: "203.0.113.4" })).toBe(`account:${A}`);
    expect(rateLimitKey({ accountId: B, apiKeyId: null, address: "203.0.113.4" })).toBe(`account:${B}`);
    // Same address, deliberately: the account claim wins, so two callers behind
    // one NAT are two accounts and not one bucket.
    expect(rateLimitKey({ accountId: A, apiKeyId: null, address: "203.0.113.4" })).not.toBe(
      rateLimitKey({ accountId: B, apiKeyId: null, address: "203.0.113.4" }),
    );
  });

  test("the Redis key a request writes names no account, including its own", async () => {
    // The digest in `bucket()` is what stops a `KEYS guard:rl:*` scan from
    // yielding a list of the accounts hitting the edge — and, read the other way,
    // it means one account's key is not a place to find another's.
    //
    // The key is read back off the transport rather than recomputed here. An
    // earlier draft built it by repeating `bucket()`'s digest in the test, which
    // is a copy of the production logic rather than a check on it — and it
    // passed with the digest deleted from `rateLimit.ts`, because both sides were
    // then trivially consistent. `bucket()` is private, so the observation point
    // is the only honest one: what `eval` was actually handed.
    const written: string[] = [];
    // One instance, delegated to — building a fresh fake per call would hand
    // every command an empty counter map and silently stop this from being a
    // limiter test at all.
    const inner = fakeRedis();
    const commands: RedisCommands = {
      async eval(script, keys, args) {
        written.push(...keys);
        return inner.eval(script, keys, args);
      },
      ping: () => inner.ping(),
    };
    const store = redisRateLimitStore({ commands });
    await limited(store, A).request("/");
    await limited(store, B).request("/");

    expect(written).toHaveLength(2);
    expect(written[0]).not.toBe(written[1]);
    for (const key of written) {
      expect(key).not.toContain(A);
      expect(key).not.toContain(B);
      // The identity does reach Redis, digested — so the assertion is about the
      // key's *text*, not about the account being unknown to the store.
      expect(key.startsWith("guard:rl:guard-api:")).toBe(true);
    }
  });

  test("a key cannot be chosen by the caller, so A cannot spend B's allowance", async () => {
    // The negative case for the *derivation* rather than for the store: every
    // header a caller can write is tried as a way to name another account, and
    // none of them reaches the bucket key.
    const store = memoryRateLimitStore();
    const seen: string[] = [];
    const app = new Hono<AuthEnv>();
    const limiter = rateLimit({
      limit: 1,
      windowMs: WINDOW_MS,
      store,
      trustedProxies: 0,
      now: () => 0,
      policy: () => "guard-api",
    });
    app.use("*", async (c, next) => {
      seen.push(rateLimitKey(keySourceOf(c, 0)));
      c.set("principal", {
        sub: `user-of-${A}`,
        accountId: A,
        scope: [],
        claims: { sub: `user-of-${A}`, account_id: A },
      });
      return limiter(c, next);
    });
    app.get("/", (c) => c.json({ ok: true }));

    for (const header of ["x-account-id", "account", "x-guard-account", "x-forwarded-account"]) {
      await app.request("/", { headers: { [header]: B, authorization: "Bearer forged" } });
    }

    // Nothing the caller wrote became a key: with no verified principal and no
    // trusted proxy the answer is the named unknown, which is the shared
    // anonymous bucket rather than anybody's account.
    expect(seen.every((key) => !key.includes(B))).toBe(true);
    expect(new Set(seen)).toEqual(new Set(["ip:unknown"]));
  });
});

// ---------------------------------------------------------------------------
// 403, and only ever for a capability or an origin
// ---------------------------------------------------------------------------

describe("a 403 is only ever a capability or an origin", () => {
  test("no account-scoped refusal in this file answers 403", async () => {
    // The rule, as an executable claim. Every negative case above asserts a
    // concrete absence; this is the one that would notice a *new* entry point
    // answering 403 for something it cannot see, because the failure mode of a
    // tenancy check is precisely that the status changed and the test still
    // passed on the body.
    const cases = [
      { what: "a token rewritten to name another account", request: gateway().request("/v1/me", asBearer(tamperPayload(await tokenFor(A), { account_id: B }))) },
      { what: "no credential at all", request: gateway().request("/v1/me") },
      { what: "a path no route serves", request: gateway(memoryApiKeyStore()).request("/v1/api-keys") },
    ];

    const statuses: string[] = [];
    for (const { what, request } of cases) {
      const res = await request;
      statuses.push(`${what} -> ${res.status}`);
    }

    // One assertion over a collected list rather than three `not.toBe(403)`
    // calls, because the failure has to name which case produced a 403 — and
    // "expected not 403, received 403" three times tells a reader nothing about
    // which of the three it was.
    expect(statuses.filter((line) => line.endsWith(" 403"))).toEqual([]);
  });

  test("the 403 guard does write is a capability failure, and names only what is missing", async () => {
    const jwt = createJwtVerifier({ issuer: identity.issuer, audience: CLIENT_ID });
    const app = new Hono<AuthEnv>();
    app.use("*", jwt.requireJwt);
    app.get("/", jwt.requireScope("invoices.write"), (c) => c.json({ ok: true }));

    const res = await app.request("/", asBearer(await tokenFor(A, "invoices.read")));

    expect(res.status).toBe(403);
    // The scope that is missing is guard's own configuration and safe to name.
    // The scopes the caller *does* hold are a fact they already know, and
    // echoing them tells a prober what else to ask for.
    const body = await res.text();
    expect(body).toContain("invoices.write");
    expect(body).not.toContain("invoices.read");
  });
});