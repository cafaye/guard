import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import {
  apiKeyPrefixOf,
  createApiKeyAuth,
  generateApiKey,
  hashApiKey,
  memoryApiKeyStore,
  type ApiKeyStore,
} from "./apiKey";
import { createJwtVerifier, type AuthEnv } from "./jwt";

const ACCOUNT = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

/**
 * The gate exactly as `index.ts` mounts it, and the scope gate is the JWT
 * verifier's own — an API key sets the same `principal` a token does, so there
 * is one scope gate in this repository rather than two that could disagree.
 */
function gated(store: ApiKeyStore) {
  const auth = createApiKeyAuth({ keys: store });
  const jwt = createJwtVerifier({ issuer: "https://identity.example", audience: "guard-test" });
  const a = new Hono<AuthEnv>();
  a.use("*", async (c, next) => {
    if (auth.hasKeyScheme(c)) return auth.authenticate(c, next);
    return next();
  });
  a.get("/", (c) => c.json({ api_key_id: c.get("apiKeyId") ?? null, subject: c.get("principal")?.sub ?? null }));
  a.get("/scoped", jwt.requireScope("invoices.write"), (c) => c.json({ ok: true }));
  return a;
}

describe("issuing a key", () => {
  test("hands back a secret, a prefix to show, and a hash to keep", () => {
    const issued = generateApiKey();

    expect(issued.key).toMatch(/^caf_[A-Za-z0-9_-]{43}$/);
    expect(issued.prefix).toBe(issued.key.slice(0, 12));
    expect(issued.prefix).not.toBe(issued.key);
    expect(issued.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("the stored hash is not the secret and not a prefix of it", () => {
    const issued = generateApiKey();

    expect(issued.key).not.toContain(issued.hash);
    expect(issued.hash.startsWith(issued.prefix)).toBe(false);
  });

  test("two keys are never the same", () => {
    const keys = new Set(Array.from({ length: 200 }, () => generateApiKey().key));

    expect(keys.size).toBe(200);
  });

  test("hashing is stable, so a lookup can find what was stored", () => {
    expect(hashApiKey("caf_abc")).toBe(hashApiKey("caf_abc"));
    expect(hashApiKey("caf_abc")).not.toBe(hashApiKey("caf_abd"));
  });
});

describe("the store", () => {
  test("stores a record under its hash, not its key", async () => {
    const store = memoryApiKeyStore();
    const issued = generateApiKey();
    await store.issue({ id: "key-1", accountId: ACCOUNT, hash: issued.hash, prefix: issued.prefix, scopes: [] });

    const found = await store.find(issued.hash);

    expect(found?.id).toBe("key-1");
    expect(JSON.stringify(found)).not.toContain(issued.key);
  });

  test("a key that was never issued is unknown, and unknown is not an error", async () => {
    expect(await memoryApiKeyStore().find(hashApiKey("caf_nope"))).toBeNull();
  });

  test("revoking removes the key immediately", async () => {
    const store = memoryApiKeyStore();
    const issued = generateApiKey();
    await store.issue({ id: "key-1", accountId: ACCOUNT, hash: issued.hash, prefix: issued.prefix, scopes: [] });
    expect(await store.find(issued.hash)).not.toBeNull();

    await store.revoke(ACCOUNT, "key-1");

    expect(await store.find(issued.hash)).toBeNull();
  });

  test("revoking a key that is already gone is not an error", async () => {
    const store = memoryApiKeyStore();

    await store.revoke(ACCOUNT, "key-1");
    await store.revoke(ACCOUNT, "key-1");
  });

  test("revoking keeps the record so an operator can see what was withdrawn", async () => {
    const store = memoryApiKeyStore();
    const issued = generateApiKey();
    await store.issue({ id: "key-1", accountId: ACCOUNT, hash: issued.hash, prefix: issued.prefix, scopes: [] });

    await store.revoke(ACCOUNT, "key-1");

    expect((await store.list(ACCOUNT)).map((k) => k.id)).toEqual(["key-1"]);
    expect((await store.list(ACCOUNT))[0]?.revokedAt).toBeGreaterThan(0);
  });

  test("a revoked key is not findable even by its exact hash", async () => {
    // `find` returning it with a flag would put the revocation decision in two
    // places; there is exactly one lookup and it does not answer for a key that
    // has been withdrawn.
    const store = memoryApiKeyStore();
    const issued = generateApiKey();
    await store.issue({ id: "key-1", accountId: ACCOUNT, hash: issued.hash, prefix: issued.prefix, scopes: [] });
    await store.revoke(ACCOUNT, "key-1");

    expect(await store.find(issued.hash)).toBeNull();
  });

  test("listing is per account and never crosses", async () => {
    const store = memoryApiKeyStore();
    const mine = generateApiKey();
    const theirs = generateApiKey();
    await store.issue({ id: "key-1", accountId: ACCOUNT, hash: mine.hash, prefix: mine.prefix, scopes: [] });
    await store.issue({ id: "key-2", accountId: "acc-other", hash: theirs.hash, prefix: theirs.prefix, scopes: [] });

    expect((await store.list(ACCOUNT)).map((k) => k.id)).toEqual(["key-1"]);
    expect(await store.list("acc-nobody")).toEqual([]);
  });

  test("the same secret issued twice is the same key, not two", async () => {
    const store = memoryApiKeyStore();
    const issued = generateApiKey();
    const record = {
      id: "key-1",
      accountId: ACCOUNT,
      hash: issued.hash,
      prefix: issued.prefix,
      scopes: [],
    };
    await store.issue(record);
    await store.issue({ ...record, id: "key-2" });

    expect((await store.find(issued.hash))?.id).toBe("key-1");
  });
});

describe("authenticating with a key", () => {
  async function issued(scopes: string[] = []) {
    const store = memoryApiKeyStore();
    const made = generateApiKey();
    await store.issue({
      id: "key-1",
      accountId: ACCOUNT,
      hash: made.hash,
      prefix: made.prefix,
      scopes,
    });
    return { store, made };
  }

  test("a valid key authenticates and names the account", async () => {
    const { store, made } = await issued();

    const res = await gated(store).request("/", { headers: { authorization: `ApiKey ${made.key}` } });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ api_key_id: "key-1", subject: ACCOUNT });
  });

  test("a revoked key is 401 on the very next request", async () => {
    const { store, made } = await issued();
    const app = gated(store);
    const headers = { authorization: `ApiKey ${made.key}` };

    expect((await app.request("/", { headers })).status).toBe(200);
    await store.revoke(ACCOUNT, "key-1");
    const res = await app.request("/", { headers });

    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/problem+json");
    expect((await res.json()) as { code: string }).toMatchObject({ code: "unauthorized" });
  });

  test("an unknown key is 401 and says nothing about which half was wrong", async () => {
    const { store } = await issued();
    const res = await gated(store).request("/", { headers: { authorization: `ApiKey ${generateApiKey().key}` } });

    expect(res.status).toBe(401);
    const body = JSON.stringify(await res.json());
    expect(body).not.toContain("unknown");
    expect(body).not.toContain("revoked");
  });

  test("a 401 body never echoes the secret back", async () => {
    const { store } = await issued();
    const made = generateApiKey();
    const res = await gated(store).request("/", { headers: { authorization: `ApiKey ${made.key}` } });

    expect(JSON.stringify(await res.json())).not.toContain(made.key);
  });

  test("a malformed credential is 401", async () => {
    const { store } = await issued();

    for (const authorization of ["ApiKey", "ApiKey   ", "ApiKey caf_too_short"]) {
      const res = await gated(store).request("/", { headers: { authorization } });
      expect(res.status).toBe(401);
    }
  });

  test("a request with no credential is left alone for the JWT gate", async () => {
    const { store } = await issued();

    const res = await gated(store).request("/");

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ api_key_id: null, subject: null });
  });

  test("a key's scopes are the scopes its caller has", async () => {
    const { store, made } = await issued(["invoices.read"]);
    const headers = { authorization: `ApiKey ${made.key}` };

    expect((await gated(store).request("/scoped", { headers })).status).toBe(403);
  });

  test("a key holding the scope passes the same gate a token would", async () => {
    const { store, made } = await issued(["invoices.write"]);

    const res = await gated(store).request("/scoped", { headers: { authorization: `ApiKey ${made.key}` } });

    expect(res.status).toBe(200);
  });
});

describe("showing a key without showing the key", () => {
  test("the prefix is the first twelve characters and nothing more", () => {
    const made = generateApiKey();

    expect(apiKeyPrefixOf(made.key)).toBe(made.key.slice(0, 12));
    expect(apiKeyPrefixOf(made.key)).toHaveLength(12);
  });

  test("a value that is not a key yields no prefix", () => {
    expect(apiKeyPrefixOf("")).toBeNull();
    expect(apiKeyPrefixOf("nope")).toBeNull();
  });
});

describe("the issuer's own surface", () => {
  test("issuing a key mints a secret nobody has seen before and stores only its hash", async () => {
    const store = memoryApiKeyStore();
    const auth = createApiKeyAuth({ keys: store });

    const secret = await auth.issue({ accountId: ACCOUNT, scopes: ["invoices.read"] });

    expect(secret.key).toMatch(/^caf_/);
    expect(secret.prefix).toBe(secret.key.slice(0, 12));
    const stored = (await store.list(ACCOUNT))[0];
    expect(stored?.hash).toBe(hashApiKey(secret.key));
    expect(JSON.stringify(stored)).not.toContain(secret.key.slice(12));
  });

  test("the issued key works, and the stored hash is all that was kept", async () => {
    const store = memoryApiKeyStore();
    const auth = createApiKeyAuth({ keys: store });
    const secret = await auth.issue({ accountId: ACCOUNT, scopes: [] });

    const res = await gated(store).request("/", { headers: { authorization: `ApiKey ${secret.key}` } });

    expect(res.status).toBe(200);
    expect((await store.list(ACCOUNT))[0]?.hash).not.toBe(secret.key);
  });
});

describe("the module's own refusals", () => {
  test("a scope that is not a scope is a startup error, not a key that cannot act", async () => {
    const store = memoryApiKeyStore();
    const auth = createApiKeyAuth({ keys: store });

    await expect(auth.issue({ accountId: ACCOUNT, scopes: [""] })).rejects.toThrow(RangeError);
    await expect(auth.issue({ accountId: ACCOUNT, scopes: [" "] })).rejects.toThrow(RangeError);
  });

  test("a key with no account is not a key", async () => {
    const auth = createApiKeyAuth({ keys: memoryApiKeyStore() });

    await expect(auth.issue({ accountId: "  ", scopes: [] })).rejects.toThrow(RangeError);
  });
});

