// The public edge, attacked.
//
// Everything in this file is a *negative* claim: the answer is that something
// cannot happen, and the test is what stops it starting to happen without
// anyone noticing. A gateway's tests otherwise assert that it does what it says,
// which is the half that was never in doubt — guard had 417 green tests before
// this file and two of them were sitting on real defects.
//
// Each claim here names the mechanism that makes it true, so "I reviewed it, it's
// fine" is never the evidence. Where a claim is a *configuration* control rather
// than a code one, the test says so, because a control that only holds in the
// deployment an operator chose is not a control.
//
// No network: identity is an injected `fetch`, the key set is built in-process
// from locally generated keys, and the Redis tier is not touched here at all.
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { createApp } from "./index";
import { SESSION_COOKIE } from "./bff/auth";
import { memorySessionStore } from "./bff/session";
import { fakeIdentity, IDENTITY_PATHS, type FakeIdentity } from "../test/fakeIdentity";
import { signToken, startJwksServer, testKey, type JwksServer, type TestKey } from "../test/jwksServer";

const AUDIENCE = "guard-test";
const ACCOUNT = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

let identity: JwksServer;
let key: TestKey;

beforeAll(async () => {
  // A key pair generated in this process for this file. It is not a key from
  // anywhere: nothing in this repository may hold a signing key that is not
  // minted on the spot and never written down.
  key = await testKey("edge-key");
  identity = await startJwksServer(key);
});

afterAll(() => identity.stop());

const seconds = (offset = 0): number => Math.floor(Date.now() / 1000) + offset;

const token = () =>
  signToken(key, {
    iss: identity.issuer,
    aud: AUDIENCE,
    sub: ACCOUNT,
    account_id: ACCOUNT,
    iat: seconds(),
    exp: seconds(60),
    scope: "profile.read",
  });

// ------------------------------------------------------------------ no SSRF

/**
 * A mutating request the way a browser sends one: an absolute URL, so the
 * same-origin gate compares `Origin` against the host actually addressed rather
 * than against Hono's `localhost` default.
 */
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  [
    `https://guard.test${path}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://guard.test",
        "sec-fetch-site": "same-origin",
        ...headers,
      },
      body: JSON.stringify(body),
    },
  ] as const;

describe("no client-controlled outbound fetch", () => {
  let upstream: FakeIdentity;

  beforeEach(() => {
    upstream = fakeIdentity();
    upstream.route("POST", IDENTITY_PATHS.register, { status: 201, json: { id: "u-1", email: "a@b.test" } });
    upstream.route("POST", IDENTITY_PATHS.session, {
      status: 200,
      json: { token: "identity-token-never-a-real-one", expires_at: new Date(Date.now() + 60_000).toISOString() },
    });
    upstream.route("DELETE", IDENTITY_PATHS.session, { status: 204 });
    upstream.route("GET", IDENTITY_PATHS.me, { status: 200, json: { id: "u-1", email: "a@b.test" } });
  });

  afterEach(() => void upstream.clear());

  /** The BFF wired to the double, with the same-origin gate satisfied. */
  const gateway = () =>
    createApp({
      bff: {
        identityUrl: "http://identity.test",
        fetch: upstream.fetch,
        sessions: memorySessionStore(),
      },
    });

  test("a body carrying absolute URLs reaches identity as data, never as a target", async () => {
    // The classic SSRF shape: a field whose value looks like a URL and is
    // somewhere a fetch is built from. guard forwards the body byte for byte to
    // a path it chose, so the only way this becomes an SSRF is if some handler
    // started reading a URL out of the payload. Every one of these values is
    // aimed at something a gateway should never reach on a caller's behalf —
    // the cloud metadata address, the Redis it shares with the limiter, and the
    // loopback identity itself.
    await gateway().request(
      ...post("/auth/register", {
        email: "a@b.test",
        password: "hunter22",
        callback_url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        redirect_uri: "http://127.0.0.1:6379/",
        avatar: "http://localhost:8080/v1/users/../../admin",
        links: [{ href: "file:///etc/passwd" }],
      }),
    );

    expect(upstream.calls).toHaveLength(1);
    const call = upstream.calls[0]!;
    // The one and only target: the configured origin plus the one constant
    // path. No scheme, no host and no path out of the body is in the URL.
    expect(call.url).toBe(`http://identity.test${IDENTITY_PATHS.register}`);
    // And the payload went out as a body, where identity can validate it.
    expect(JSON.parse(call.body ?? "{}")).toMatchObject({ callback_url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" });
  });

  test("no request header can move the identity target", async () => {
    // A header a caller chose is the other place a URL can hide. If any handler
    // built a fetch from one, this is where it would show: a request that tries
    // to redirect guard's outbound call to the metadata service, through every
    // header name that has ever been used for exactly that.
    await gateway().request(
      ...post("/auth/login", { email: "a@b.test", password: "hunter22" }, {
        "x-forwarded-host": "169.254.169.254",
        "x-original-url": "http://169.254.169.254/",
        "x-rewrite-url": "http://127.0.0.1:6379/",
        host: "169.254.169.254",
        "x-identity-url": "http://evil.test/",
        referer: "http://169.254.169.254/",
      }),
    );

    expect(upstream.calls).toHaveLength(1);
    expect(upstream.calls[0]!.url).toBe(`http://identity.test${IDENTITY_PATHS.session}`);
  });

  test("a redirect from identity is not followed to a re-checked target", async () => {
    // The reason this is a *test* and not a comment: `fetch` follows a 3xx by
    // default, so the question is whether guard has ever handed a
    // caller-influenced URL to something that would follow one. The answer here
    // is that there is no caller-influenced URL to follow — but a `Location`
    // coming back from identity is still worth pinning, because a *future*
    // handler that fetched a caller-supplied URL would inherit this default.
    //
    // What guard does today is not follow: the call's response is inspected for
    // a status it recognises and the body is parsed as JSON, and a 302 is not a
    // status any of the four routes accepts.
    upstream.route("POST", IDENTITY_PATHS.register, {
      status: 302,
      json: { location: "http://169.254.169.254/latest/meta-data/" },
    });

    const res = await gateway().request(...post("/auth/register", { email: "a@b.test", password: "hunter22" }));

    expect(res.status).toBe(503);
    // Exactly one hop. A followed redirect would be a second recorded call.
    expect(upstream.calls).toHaveLength(1);
    expect(upstream.calls[0]!.url).toBe(`http://identity.test${IDENTITY_PATHS.register}`);
    expect(await res.text()).not.toContain("169.254.169.254");
  });

  test("the JWKS URL is configuration, never a request header or query", async () => {
    // The other outbound call guard makes. Its target is `${issuer}/.well-known/…`
    // from `IDENTITY_JWKS_URL` — an operator setting, validated at construction.
    const gateway = createApp({ jwt: { issuer: identity.issuer, audience: AUDIENCE } });

    await gateway.request("/v1/me", {
      headers: {
        authorization: `Bearer ${await token()}`,
        "x-jwks-url": "http://169.254.169.254/keys",
        "x-forwarded-host": "169.254.169.254",
      },
    });

    // One fetch, and it is the configured well-known path on the configured
    // issuer. Nothing a caller sent could have added a hop.
    expect(identity.requests).toEqual(["/.well-known/jwks.json"]);
  });
});

// -------------------------------------------------- path traversal and routing

describe("path handling: a route is chosen by matching, not by string surgery", () => {
  const gateway = () => createApp({ jwt: { issuer: identity.issuer, audience: AUDIENCE } });

  test("every spelling of /v1/me that reaches a route still meets the auth gate", async () => {
    // The question a gateway built by string manipulation cannot answer. If
    // `/v1/../v1/me` or `/v1/%2e%2e/v1/me` normalises to a route on the way *in*
    // but is compared as a prefix on the way to the middleware, the handler runs
    // with no token. Every shape below is the same route, so every one of them
    // has to be a 401 and not a 200 or a 404 that skipped the gate.
    const spellings = [
      "/v1/me",
      "/v1/./me",
      "/v1/../v1/me",
      "/v1//me",
      "/v1/%2e/me",
      "/v1/%2e%2e/v1/me",
      "/v1/me/",
      "/v1/me%2f",
      "/v1/me%00",
      "/v1/me;jsessionid=1",
      "/v1/me?next=/admin",
      "/v1/me#fragment",
      "/%76%31/me",
    ];

    const app = gateway();
    for (const path of spellings) {
      const res = await app.request(path, { headers: { authorization: `Bearer ${await token()}` } });
      const anonymous = await app.request(path);

      // The claim is narrow and it is the one that matters: no spelling of the
      // route reaches a handler without a token. 401 means the gate saw it;
      // 404 means no route matched it. A 2xx on the anonymous request is the
      // defect this test exists to catch, and nothing else about the status is
      // interesting.
      expect(`${path} anon=${anonymous.status} auth=${res.status}`).not.toContain("anon=200");
      expect(`${path} anon=${anonymous.status}`).toMatch(/anon=(401|404)/);
      // And a verified token never gets less than an unverified one on the same
      // path, which is what would mean the gate and the router disagree.
      expect(res.status).toBeGreaterThanOrEqual(anonymous.status === 404 ? 404 : 200);
    }
  });

  test("a traversal out of /v1 does not land on a route outside the gate", async () => {
    // The complement: paths that escape the `/v1/*` prefix must not resolve to
    // something a browser surface or a probe serves. `/auth/*` is the one an
    // attacker wants — it mints a session cookie.
    const app = gateway();
    for (const path of [
      "/v1/../auth/login",
      "/v1/%2e%2e/auth/login",
      "/v1/..%2fauth%2flogin",
      "/v1/../healthz",
      "/v1/../readyz",
    ]) {
      const res = await app.request(path, {
        method: "POST",
        headers: { origin: "https://guard.test", "content-type": "application/json" },
        body: JSON.stringify({ email: "a@b.test", password: "hunter22" }),
      });

      // The claim is that none of these mints a session or reaches a probe. A
      // 404 means no route matched; a 401 means the `/v1/*` gate caught it
      // *before* the route table, which is the stronger answer. What must never
      // happen is a 2xx with a cookie, or a 200 from a probe path that should
      // have been throttled and authenticated.
      expect(`${path} -> ${res.status}`).toMatch(/-> (401|404)$/);
      expect(res.headers.get("set-cookie")).toBeNull();
      expect(await res.text()).not.toContain("guard listening");
    }
  });

  test("the probe endpoints are only the two exact paths, not prefixes of them", async () => {
    // The limiter exempts `/healthz` and `/readyz` by name. An exemption that
    // matched by prefix would exempt `/healthz-anything`, and this is where a
    // future route under either prefix would silently become unthrottled.
    const app = createApp({
      rateLimit: { limits: { default: { limit: 1, windowMs: 60_000, policy: "guard-api" }, routes: {} } },
    });

    expect((await app.request("/healthz")).status).toBe(200);
    expect((await app.request("/readyz")).status).toBe(200);
    // Repeats stay exempt — that is the contract, and the reason a throttled
    // probe is not a thing.
    expect((await app.request("/healthz")).status).toBe(200);
    expect((await app.request("/readyz")).status).toBe(200);

    // A near miss is traffic. The first of these spends the allowance and the
    // second is refused, which is what "not exempt" has to mean in practice.
    expect((await app.request("/healthz/sub")).status).toBe(404);
    const refused = await app.request("/healthz/sub");
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toBeTruthy();
    expect(refused.headers.get("ratelimit-limit")).toBe("1");
  });
});

// ------------------------------------------------------- header and log safety

describe("nothing a caller sends reaches a header or a log line", () => {
  /**
   * The log, captured rather than printed. Several cases below assert that a
   * caller's value reached the log and did NOT reach the response, which is
   * only checkable if the log is in hand.
   */
  const logged: unknown[][] = [];
  let realConsoleError: typeof console.error;

  beforeEach(() => {
    logged.length = 0;
    realConsoleError = console.error;
    console.error = (...args: unknown[]) => void logged.push(args);
  });

  afterEach(() => {
    console.error = realConsoleError;
  });

  test("CRLF in a forwarded path cannot inject a response header", async () => {
    // Header injection, on the one route that echoes a path back: `problem()`
    // puts the request path in `instance`. A path carrying CRLF would split a
    // response header if the value were not encoded, and `c.json` does encode
    // it — but "does encode it" is exactly the kind of claim that needs a test
    // rather than a reading of the source.
    const app = createApp();
    const res = await app.request("/v1/me%0d%0aX-Injected:%20yes", {
      headers: { authorization: "Bearer not.a.token" },
    });

    expect(res.headers.get("x-injected")).toBeNull();
    // The raw CR and LF are gone from the body entirely, not merely escaped.
    const body = await res.text();
    expect(body).not.toContain("\r");
    expect(body).not.toContain("\n");
  });

  test("a CRLF in a rate-limit-affecting header never reaches guard at all", async () => {
    // The header path a gateway is most likely to get wrong: a value read from
    // the request and written into a response header. The result here is
    // stronger than a filter — the runtime refuses to *construct* a request
    // whose header value carries a line break, so the bytes never arrive and
    // there is nothing for guard to sanitise. Asserting the refusal is what
    // stops this test quietly becoming a claim about a filter that does not
    // exist.
    //
    // The second half is guard's own: `X-Forwarded-For` is the one caller-chosen
    // header guard reads, and it never reaches a response header at all — it
    // becomes a SHA-256 digest inside a bucket name.
    expect(() =>
      new Request("https://guard.test/", { headers: { "x-forwarded-for": "203.0.113.4\r\nX-Injected: yes" } }),
    ).toThrow();

    const app = createApp({
      rateLimit: { limits: { default: { limit: 5, windowMs: 60_000, policy: "guard-api" }, routes: {} } },
    });
    const res = await app.request("/", { headers: { "x-forwarded-for": "203.0.113.4" } });

    expect(res.headers.get("x-injected")).toBeNull();
    for (const [, value] of res.headers) {
      expect(String(value)).not.toContain("203.0.113.4");
    }
  });

  test("the rate-limit policy names in the headers come from configuration alone", async () => {
    // `RateLimit-Policy` is a structured field, and the policy name is the one
    // thing guard writes into it from a table. A name carrying a second field
    // item is refused at *construction* rather than escaped — so this is a
    // refusal to boot, not a 500 on the first request, which is the stronger of
    // the two answers and is asserted as such.
    expect(() =>
      createApp({
        rateLimit: {
          limits: { default: { limit: 5, windowMs: 60_000, policy: 'evil",r=999;t=1' }, routes: {} },
        },
      }),
    ).toThrow(RangeError);

    // And the configured names that DO ship are the only thing in the header.
    const app = createApp({
      rateLimit: { limits: { default: { limit: 7, windowMs: 60_000, policy: "guard-api" }, routes: {} } },
    });
    const res = await app.request("/");

    expect(res.headers.get("ratelimit-policy")).toBe('"guard-api";q=7;w=60');
    // `t` is the effective window to replenishment, not the policy window — the
    // countdown the draft means by it — so it is the store's number, not 60.
    expect(res.headers.get("ratelimit")).toMatch(/^"guard-api";r=6;t=\d+$/);
  });

  test("an error from identity is logged with its detail and returned without it", async () => {
    // The two halves of the rule that matters most for a gateway, on the one
    // place an upstream's internals could reach a browser. A 500 from identity
    // carrying a host and a port must not put either in the response body.
    const upstream = fakeIdentity();
    upstream.route("POST", IDENTITY_PATHS.session, {
      status: 500,
      text: "Error: connect ECONNREFUSED 10.11.12.13:5432 password=hunter2",
    });

    const app = createApp({
      bff: { identityUrl: "http://identity.test", fetch: upstream.fetch, sessions: memorySessionStore() },
    });

    const res = await app.request(
      ...post("/auth/login", { email: "a@b.test", password: "hunter22" }),
    );

    expect(res.status).toBe(503);
    const body = await res.text();
    for (const secret of ["10.11.12.13", "5432", "hunter2", "ECONNREFUSED", "identity.test"]) {
      expect(body).not.toContain(secret);
    }
  });

  test("an identity 5xx is recorded, not silently swallowed", async () => {
    // The half of the rule above that does not currently hold.
    //
    // `unreachable()` carries this in its own comment — "The URL and the status
    // that produced it are in the log either way" — and `unusable()` exists as a
    // *separate* 503 precisely so an operator can tell "identity is down" from
    // "identity answered with rubbish". Neither is true of an upstream 5xx: the
    // transport did not throw, so `call()`'s catch never runs, and the handler
    // falls through to `unusable()` without a word. The browser says 503 and
    // guard's log says nothing at all.
    //
    // That is a silent outage. Every login in a deployment is failing with one
    // status, nothing is recorded, and the operator has no signal to act on
    // except the browsers of their users.
    const upstream = fakeIdentity();
    upstream.route("POST", IDENTITY_PATHS.session, {
      status: 500,
      text: "Error: connect ECONNREFUSED 10.11.12.13:5432 password=hunter2",
    });

    const app = createApp({
      bff: { identityUrl: "http://identity.test", fetch: upstream.fetch, sessions: memorySessionStore() },
    });

    const res = await app.request(...post("/auth/login", { email: "a@b.test", password: "hunter22" }));

    expect(res.status).toBe(503);

    // Recorded. The URL and the status are what makes the 503 diagnosable; the
    // upstream *body* is deliberately not required, because a dependency's
    // error page is exactly where a credential would be, and the rule above is
    // that nothing like that is ever written down.
    const line = JSON.stringify(logged);
    expect(line).toContain("identity.test");
    expect(line).toContain("500");

    // And the upstream's own body is not what got logged, for the same reason
    // it is not in the response.
    expect(line).not.toContain("hunter2");
    expect(line).not.toContain("10.11.12.13");
  });

  test("the recorded shape is what identity actually sent", async () => {
    // The half that keeps the log line honest. A body can only be read once, so
    // a handler that parses it for the shape check and then parses it *again* to
    // decide the shape reports "no body" about a response that carried one — a
    // log line that lies to exactly the operator who is reading it at 3am.
    const upstream = fakeIdentity();
    // A 200 whose document is not a user: the answer is unusable, and the record
    // has to say what arrived.
    upstream.route("GET", IDENTITY_PATHS.me, { status: 200, json: { unexpected: "shape" } });

    const app = createApp({
      bff: { identityUrl: "http://identity.test", fetch: upstream.fetch, sessions: memorySessionStore() },
    });

    // Sign in so there is a session for /auth/me to present.
    upstream.route("POST", IDENTITY_PATHS.session, {
      status: 200,
      json: { token: "not-a-real-token", expires_at: new Date(Date.now() + 60_000).toISOString() },
    });
    const login = await app.request(...post("/auth/login", { email: "a@b.test", password: "hunter22" }));
    const cookie = login.headers.get("set-cookie")?.split(";")[0];
    expect(cookie).toBeTruthy();

    const res = await app.request("https://guard.test/auth/me", { headers: { cookie: cookie! } });

    expect(res.status).toBe(503);
    const line = JSON.stringify(logged);
    expect(line).toContain("http://identity.test/v1/me");
    expect(line).toContain("answered 200");
    // A JSON document really did arrive, so the line must not claim otherwise.
    expect(line).toContain("a JSON document");
    expect(line).not.toContain("no body");
    expect(line).not.toContain("not JSON");
  });

  test("an identity answer that is not JSON is recorded as not JSON", async () => {
    // The same line, the other shape, and the reason `unusable` separates `null`
    // from a document: `typeof null` is `"object"`, so the obvious test calls an
    // HTML error page "a JSON document" and an operator debugging a dependency
    // that started returning a login page is told the wrong thing.
    const upstream = fakeIdentity();
    upstream.route("GET", IDENTITY_PATHS.me, {
      status: 200,
      text: "<html><body>Sign in to continue</body></html>",
    });

    const app = createApp({
      bff: { identityUrl: "http://identity.test", fetch: upstream.fetch, sessions: memorySessionStore() },
    });

    upstream.route("POST", IDENTITY_PATHS.session, {
      status: 200,
      json: { token: "not-a-real-token", expires_at: new Date(Date.now() + 60_000).toISOString() },
    });
    const login = await app.request(...post("/auth/login", { email: "a@b.test", password: "hunter22" }));
    const cookie = login.headers.get("set-cookie")?.split(";")[0]!;

    const res = await app.request("https://guard.test/auth/me", { headers: { cookie } });

    expect(res.status).toBe(503);
    const line = JSON.stringify(logged);
    expect(line).toContain("answered 200 (not JSON)");
    // And the intercepted login page itself is never written down.
    expect(line).not.toContain("Sign in to continue");
    expect(await res.text()).not.toContain("Sign in to continue");
  });

  test("a session id from a cookie is never echoed back into the response", async () => {
    // The cookie is a bearer credential. `logout` and `me` both read it, and
    // neither may put it in a body, a header or a `Location`.
    const upstream = fakeIdentity();
    upstream.route("GET", IDENTITY_PATHS.me, { status: 401 });

    const app = createApp({
      bff: { identityUrl: "http://identity.test", fetch: upstream.fetch, sessions: memorySessionStore() },
    });

    const forged = "00000000-0000-4000-8000-000000000000";
    const res = await app.request("/auth/me", { headers: { cookie: `${SESSION_COOKIE}=${forged}` } });

    expect(res.status).toBe(401);
    const body = await res.text();
    expect(body).not.toContain(forged);
    expect(res.headers.get("location")).toBeNull();
  });
});