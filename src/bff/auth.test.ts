import { describe, expect, test } from "bun:test";
import { createApp } from "../index";
import { createBffAuth, identityProbe, SESSION_COOKIE, type BffOptions } from "./auth";
import { memorySessionStore, type SessionStore } from "./session";
import { fakeIdentity, IDENTITY_PATHS, type FakeIdentity, type Reply } from "../../test/fakeIdentity";

const IDENTITY_URL = "http://identity.test:8080";
/** The origin a browser is on. The gate compares hosts, so this is the host. */
const CONSOLE = "https://console.cafaye.com";
const HOST = "console.cafaye.com";

const USER = { id: "3f2504e0-4f89-41d3-9a0c-0305e82c3301", email: "ada@cafaye.com" };
const TOKEN = "identity-issued-token";
/** An hour out, computed rather than written down: a literal would make this
 *  suite's result depend on the hour it runs. Rounded to a whole second because
 *  a cookie's `Expires` has one-second resolution and the round trip is asserted. */
const EXPIRES_AT = new Date(Math.ceil((Date.now() + 3_600_000) / 1000) * 1000).toISOString();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// --------------------------------------------------------------------- harness

type Harness = {
  app: ReturnType<typeof createApp>;
  identity: FakeIdentity;
  sessions: MemoryStore;
};

/** The v0 store, which can report its size — so "nothing was stored" is assertable. */
type MemoryStore = SessionStore & { size(): number };

function harness(options: Partial<BffOptions> = {}): Harness {
  const identity = fakeIdentity();
  const sessions = (options.sessions ?? memorySessionStore()) as MemoryStore;
  const app = createApp({ bff: { identityUrl: IDENTITY_URL, fetch: identity.fetch, sessions, ...options } });
  return { app, identity, sessions };
}

/** Identity answers a login the way a healthy one does. */
function loginSucceeds(identity: FakeIdentity, reply: Partial<Reply> = {}): void {
  identity.route("POST", IDENTITY_PATHS.session, {
    status: 200,
    json: { token: TOKEN, expires_at: EXPIRES_AT },
    ...reply,
  });
}

/**
 * A mutating request the way a browser sends one: same-origin, JSON, a cookie
 * jar. Every auth test goes through here, so "the gate let it through" is never
 * something a test asserted by accident.
 */
function post(
  path: string,
  body?: unknown,
  headers: Record<string, string | undefined> = {},
  cookie?: string,
): [string, RequestInit] {
  const sent: Record<string, string> = {};
  if (body !== undefined) {
    sent["content-type"] = "application/json";
  }
  for (const [name, value] of Object.entries({
    origin: CONSOLE,
    "sec-fetch-site": "same-origin",
    ...headers,
  })) {
    if (value !== undefined) sent[name] = value;
  }
  if (cookie !== undefined) sent.cookie = cookie;

  return [
    `https://${HOST}${path}`,
    { method: "POST", headers: sent, body: body === undefined ? undefined : JSON.stringify(body) },
  ];
}

function get(path: string, headers: Record<string, string> = {}, cookie?: string): [string, RequestInit] {
  return [
    `https://${HOST}${path}`,
    { method: "GET", headers: cookie === undefined ? headers : { ...headers, cookie } },
  ];
}

/** `name=value; Path=/; HttpOnly` as a record a test can assert field by field. */
type ParsedCookie = { name: string; value: string; attributes: Record<string, string | true> };

function parseSetCookie(response: Response): ParsedCookie {
  const header = response.headers.get("set-cookie");
  if (header === null) throw new Error("expected a Set-Cookie header, got none");

  const [pair, ...rest] = header.split(";");
  const [name, value] = (pair ?? "").split("=");
  const attributes: Record<string, string | true> = {};

  for (const part of rest) {
    const [key, attributeValue] = part.trim().split("=");
    attributes[key ?? ""] = attributeValue === undefined ? true : attributeValue;
  }

  return { name: name ?? "", value: value ?? "", attributes };
}

/** The session id a login handed the browser. */
function sessionIdOf(response: Response): string {
  return parseSetCookie(response).value;
}

function cookieHeader(response: Response): string {
  return `${SESSION_COOKIE}=${sessionIdOf(response)}`;
}

/** Logs in and returns the session id the browser was given. */
async function signedIn(h: Harness): Promise<string> {
  loginSucceeds(h.identity);
  const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" }));
  expect(res.status).toBe(200);
  return sessionIdOf(res);
}

/** The rejection envelope, as the assertions read it. */
type Envelope = {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance: string;
  code: string;
  trace_id: string;
  errors?: { field: string; code: string }[];
};

async function envelopeOf(response: Response): Promise<Envelope> {
  return (await response.json()) as Envelope;
}

async function expectProblem(
  response: Response,
  expected: { status: number; code: string; detail: string; instance: string },
): Promise<Envelope> {
  expect(response.status).toBe(expected.status);
  expect(response.headers.get("content-type")).toContain("application/problem+json");

  const body = await envelopeOf(response);
  expect(body).toMatchObject({
    type: `https://errors.cafaye.com/${expected.code}`,
    status: expected.status,
    code: expected.code,
    detail: expected.detail,
    instance: expected.instance,
  });
  expect(body.trace_id).toMatch(/^[0-9a-f]{32}$/);
  expect(response.headers.get("x-trace-id")).toBe(body.trace_id);

  return body;
}

// -------------------------------------------------------------- POST /auth/register

describe("POST /auth/register", () => {
  test("201 with the account identity created, and no cookie", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, { status: 201, json: USER });

    const res = await h.app.request(...post("/auth/register", { email: USER.email, password: "hunter22" }));

    expect(res.status).toBe(201);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual(USER);
    // A registration is not a login. Nothing here may hand the browser a
    // session, or "sign up" would be a second way in.
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("the caller's body reaches identity verbatim, and the URL comes from IDENTITY_URL", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, { status: 201, json: USER });

    await h.app.request(...post("/auth/register", { email: USER.email, password: "hunter22" }));

    const [call] = h.identity.callsTo("POST", IDENTITY_PATHS.register);
    expect(call?.url).toBe(`${IDENTITY_URL}/v1/users`);
    expect(call?.body).toBe(JSON.stringify({ email: USER.email, password: "hunter22" }));
  });

  test("only id and email are returned, whatever else identity puts in the body", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, {
      status: 201,
      json: { ...USER, password_digest: "$2a$10$…", tenant_id: "…" },
    });

    const res = await h.app.request(...post("/auth/register", { email: USER.email, password: "hunter22" }));

    expect(await res.json()).toEqual(USER);
  });

  test("422 becomes core's validation_failed envelope and keeps the field errors", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, {
      status: 422,
      json: { code: "validation_failed", detail: "…", errors: [{ field: "email", code: "invalid_format" }] },
    });

    const res = await h.app.request(...post("/auth/register", { email: "nope", password: "x" }));

    const body = await expectProblem(res, {
      status: 422,
      code: "validation_failed",
      detail: "the request has an invalid field",
      instance: "/auth/register",
    });
    // A sign-up form renders errors[]; dropping it would leave the browser to
    // show "something went wrong" for a field identity named exactly.
    expect(body.errors).toEqual([{ field: "email", code: "invalid_format" }]);
  });

  test("field errors identity did not send, or sent as rubbish, are dropped rather than echoed", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, {
      status: 422,
      json: { errors: "not an array" },
    });
    h.identity.route("POST", IDENTITY_PATHS.session, { status: 422, json: { errors: [{ field: 7, code: {} }] } });

    const res = await h.app.request(...post("/auth/register", { email: "nope", password: "x" }));
    const body = await expectProblem(res, {
      status: 422,
      code: "validation_failed",
      detail: "the request has an invalid field",
      instance: "/auth/register",
    });

    expect(body.errors).toBeUndefined();
  });

  test("a 201 whose body is not JSON is 503, not a parse error", async () => {
    // A proxy answering 201 with a login page is the shape this catches.
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, { status: 201, text: "<html>sign in</html>" });

    const res = await h.app.request(...post("/auth/register", { email: USER.email, password: "hunter22" }));

    await expectProblem(res, {
      status: 503,
      code: "unavailable",
      detail: "the authentication service answered with something unusable",
      instance: "/auth/register",
    });
  });

  test("409 becomes conflict", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, { status: 409, json: { code: "conflict" } });

    const res = await h.app.request(...post("/auth/register", { email: USER.email, password: "hunter22" }));

    await expectProblem(res, {
      status: 409,
      code: "conflict",
      detail: "an account already exists for that email address",
      instance: "/auth/register",
    });
  });

  test("a body that is not a JSON object is 400 and identity is never called", async () => {
    const h = harness();

    const res = await h.app.request("https://console.cafaye.com/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json", origin: CONSOLE, "sec-fetch-site": "same-origin" },
      body: '"not an object"',
    });

    await expectProblem(res, {
      status: 400,
      code: "invalid_json",
      detail: "the request body must be a JSON object",
      instance: "/auth/register",
    });
    expect(h.identity.calls).toHaveLength(0);
  });

  test("a JSON array is not an object either", async () => {
    const h = harness();

    const res = await h.app.request("https://console.cafaye.com/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json", origin: CONSOLE, "sec-fetch-site": "same-origin" },
      body: "[1,2]",
    });

    expect(res.status).toBe(400);
    expect(h.identity.calls).toHaveLength(0);
  });

  test("a body larger than guard will forward is 413, and is not read into memory", async () => {
    // An anonymous caller chooses how many bytes this process buffers. identity
    // caps a body at 4 KiB, so anything larger is refused by a reader that is
    // already reading — and an edge that buffered it first would be the one
    // holding it.
    const h = harness();
    const oversized = JSON.stringify({ email: USER.email, password: "x".repeat(8 << 10) });

    const res = await h.app.request("https://console.cafaye.com/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json", origin: CONSOLE, "sec-fetch-site": "same-origin" },
      body: oversized,
    });

    await expectProblem(res, {
      status: 413,
      code: "payload_too_large",
      detail: "the request body is larger than 4096 bytes",
      instance: "/auth/register",
    });
    expect(h.identity.calls).toHaveLength(0);
  });

  test("a body just inside the limit is forwarded", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, { status: 201, json: USER });
    const body = JSON.stringify({ email: USER.email, password: "x".repeat(1 << 10) });

    const res = await h.app.request("https://console.cafaye.com/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json", origin: CONSOLE, "sec-fetch-site": "same-origin" },
      body,
    });

    expect(res.status).toBe(201);
    expect(h.identity.callsTo("POST", IDENTITY_PATHS.register)[0]?.body).toBe(body);
  });

  test("a 200 from a create is 503, not a body guard made up", async () => {
    // identity's contract for this route is 201 and nothing else. An identity
    // answering 200 is a different service, and echoing its body would be
    // guard reporting a registration that may never have happened.
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, { status: 200, json: USER });

    const res = await h.app.request(...post("/auth/register", { email: USER.email, password: "hunter22" }));

    await expectProblem(res, {
      status: 503,
      code: "unavailable",
      detail: "the authentication service answered with something unusable",
      instance: "/auth/register",
    });
  });

  test("identity being unreachable is 503 and the detail names no host", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.register, { status: 500, fail: new Error("dial 10.0.0.5:8080: refused") });

    const res = await h.app.request(...post("/auth/register", { email: USER.email, password: "hunter22" }));

    const body = await expectProblem(res, {
      status: 503,
      code: "unavailable",
      detail: "the authentication service could not be reached",
      instance: "/auth/register",
    });
    // The address and the host are the platform's, not the caller's.
    expect(JSON.stringify(body)).not.toContain("10.0.0.5");
    expect(JSON.stringify(body)).not.toContain("identity.test");
  });

  test("a hung identity is bounded by the timeout rather than holding the request", async () => {
    const h = harness({ timeoutMs: 25 });
    h.identity.route("POST", IDENTITY_PATHS.register, { status: 200, hang: true });

    const res = await h.app.request(...post("/auth/register", { email: USER.email, password: "hunter22" }));

    expect(res.status).toBe(503);
  });
});

// ----------------------------------------------------------------- POST /auth/login

describe("POST /auth/login", () => {
  test("200 and a session cookie that is not identity's token", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" }));

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");

    const cookie = parseSetCookie(res);
    expect(cookie.value).toMatch(UUID);
    // The whole point of the BFF: the browser's credential is a session id
    // guard minted. Identity's token lives in guard's store and nowhere else.
    expect(cookie.value).not.toBe(TOKEN);
    expect(res.headers.get("set-cookie")).not.toContain(TOKEN);
    expect(await res.text()).not.toContain(TOKEN);
  });

  test("the cookie is __Host- prefixed, HttpOnly, Secure, SameSite=Lax and Path=/", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const { name, attributes } = parseSetCookie(
      await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" })),
    );

    // __Host- is a contract the browser enforces: Secure, Path=/ and no Domain.
    // Together they make the cookie un-settable by a subdomain, which is the
    // cookie-fixation vector a plain `session` cookie leaves open.
    expect(name).toBe("__Host-bff-session");
    expect(attributes.Secure).toBe(true);
    expect(attributes.Path).toBe("/");
    expect(attributes.HttpOnly).toBe(true);
    expect(attributes.SameSite).toBe("Lax");
    expect(attributes.Domain).toBeUndefined();
    // Lax and not Strict: a Strict cookie is not sent on the top-level
    // navigation a user follows straight after signing in.
    expect(attributes.SameSite).not.toBe("Strict");
  });

  test("the cookie expires when the session identity minted expires", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const { attributes } = parseSetCookie(
      await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" })),
    );

    expect(new Date(String(attributes.Expires)).toISOString()).toBe(EXPIRES_AT);
  });

  test("the token is in the store, keyed by the session id the browser holds", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" }));

    expect(await h.sessions.get(sessionIdOf(res))).toEqual({
      token: TOKEN,
      expiresAt: new Date(EXPIRES_AT).getTime(),
    });
  });

  test("two logins are two sessions, and neither reuses the other's id", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const first = sessionIdOf(await h.app.request(...post("/auth/login", { email: USER.email, password: "a" })));
    const second = sessionIdOf(await h.app.request(...post("/auth/login", { email: USER.email, password: "a" })));

    // A shared id would be a session fixation: logging in must never land the
    // caller in a session somebody else could have named in advance.
    expect(first).not.toBe(second);
    expect(await h.sessions.get(first)).not.toBeNull();
    expect(await h.sessions.get(second)).not.toBeNull();
  });

  test("the body says when the session runs out and never carries the token", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" }));
    const body = (await res.json()) as Record<string, unknown>;

    expect(body).toEqual({ expires_at: EXPIRES_AT });
    expect(body).not.toHaveProperty("token");
  });

  test("identity's 401 is a 401 in core's envelope, with no cookie", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.session, { status: 401, json: { code: "unauthorized" } });

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "wrong" }));

    await expectProblem(res, {
      status: 401,
      code: "unauthorized",
      // One sentence for every refused credential. Varying it per case is how a
      // login endpoint becomes an account-enumeration oracle.
      detail: "email or password is not correct",
      instance: "/auth/login",
    });
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("identity's 423 is a 423 and its Retry-After is carried through", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.session, {
      status: 423,
      json: { code: "account_locked" },
      headers: { "Retry-After": "900" },
    });

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "wrong" }));

    await expectProblem(res, {
      status: 423,
      code: "account_locked",
      detail: "too many failed sign-in attempts for this account",
      instance: "/auth/login",
    });
    // Collapsing the lockout into a 401 would tell a correct password to try
    // again and be refused again for a quarter of an hour.
    expect(res.headers.get("retry-after")).toBe("900");
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("an identity that is not there is 503, with no cookie and nothing stored", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.session, {
      status: 200,
      json: { token: TOKEN, expires_at: EXPIRES_AT },
      fail: new Error("connect ECONNREFUSED 10.0.0.5:8080"),
    });

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" }));

    await expectProblem(res, {
      status: 503,
      code: "unavailable",
      detail: "the authentication service could not be reached",
      instance: "/auth/login",
    });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(h.sessions.size()).toBe(0);
  });

  test("a login with no token is 503 and nothing is stored", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.session, { status: 200, json: { expires_at: EXPIRES_AT } });

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" }));

    await expectProblem(res, {
      status: 503,
      code: "unavailable",
      detail: "the authentication service answered with something unusable",
      instance: "/auth/login",
    });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(h.sessions.size()).toBe(0);
  });

  test("a login with an unparseable expiry is 503 and nothing is stored", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.session, {
      status: 200,
      json: { token: TOKEN, expires_at: "whenever" },
    });

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" }));

    expect(res.status).toBe(503);
    expect(h.sessions.size()).toBe(0);
  });

  test("a session with an expiry already in the past is not a session", async () => {
    const h = harness();
    h.identity.route("POST", IDENTITY_PATHS.session, {
      status: 200,
      json: { token: TOKEN, expires_at: "2020-01-01T00:00:00.000Z" },
    });

    const res = await h.app.request(...post("/auth/login", { email: USER.email, password: "hunter22" }));

    // Handing out a cookie the store will refuse on the next request would be a
    // login that reports success and then signs the user straight out.
    expect(res.status).toBe(503);
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(h.sessions.size()).toBe(0);
  });
});

// ---------------------------------------------------------------- POST /auth/logout

describe("POST /auth/logout", () => {
  test("204, the cookie is cleared, and identity is told to revoke", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("DELETE", IDENTITY_PATHS.session, { status: 204 });

    const res = await h.app.request(...post("/auth/logout", undefined, {}, `${SESSION_COOKIE}=${sessionId}`));

    expect(res.status).toBe(204);

    // identity revokes the token, and it is the token in the store — the one
    // the browser never sees.
    const [call] = h.identity.callsTo("DELETE", IDENTITY_PATHS.session);
    expect(call?.token).toBe(TOKEN);
    expect(await h.sessions.get(sessionId)).toBeNull();
  });

  test("clearing the cookie repeats every attribute the setting cookie had", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("DELETE", IDENTITY_PATHS.session, { status: 204 });

    const res = await h.app.request(...post("/auth/logout", undefined, {}, `${SESSION_COOKIE}=${sessionId}`));
    const { value, attributes } = parseSetCookie(res);

    // A deletion that differs in name, domain or path is a different cookie to
    // the browser, and the stale one survives: "sign out" appears to do nothing.
    expect(value).toBe("");
    expect(attributes["Max-Age"]).toBe("0");
    expect(attributes.Path).toBe("/");
    expect(attributes.Secure).toBe(true);
    expect(attributes.HttpOnly).toBe(true);
    expect(attributes.SameSite).toBe("Lax");
  });

  test("the session is gone afterwards, so /auth/me is a 401 with no identity call", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("DELETE", IDENTITY_PATHS.session, { status: 204 });
    h.identity.clear();

    await h.app.request(...post("/auth/logout", undefined, {}, `${SESSION_COOKIE}=${sessionId}`));
    h.identity.clear();

    const res = await h.app.request(...get("/auth/me", {}, `${SESSION_COOKIE}=${sessionId}`));

    expect(res.status).toBe(401);
    // Nothing left in the store means nothing to ask identity about: a
    // revocation the browser cannot use should cost no round trip either.
    expect(h.identity.calls).toHaveLength(0);
  });

  test("no cookie is a 401 and identity is never called", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const res = await h.app.request(...post("/auth/logout"));

    await expectProblem(res, {
      status: 401,
      code: "unauthorized",
      detail: "no session cookie was presented",
      instance: "/auth/logout",
    });
    expect(h.identity.calls).toHaveLength(0);
  });

  test("a cookie the store has forgotten still signs the browser out", async () => {
    // What a restart or a swept map leaves behind. Nothing to revoke, and the
    // browser is not signed in — refusing here is what makes sign-out look
    // broken.
    const h = harness();

    const res = await h.app.request(
      ...post("/auth/logout", undefined, {}, `${SESSION_COOKIE}=3f2504e0-4f89-41d3-9a0c-0305e82c3301`),
    );

    expect(res.status).toBe(204);
    expect(parseSetCookie(res).value).toBe("");
    expect(h.identity.calls).toHaveLength(0);
  });

  test("a session identity has already revoked is a 204, because that is the end state asked for", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("DELETE", IDENTITY_PATHS.session, { status: 401, json: { code: "unauthorized" } });

    const res = await h.app.request(...post("/auth/logout", undefined, {}, `${SESSION_COOKIE}=${sessionId}`));

    expect(res.status).toBe(204);
    expect(await h.sessions.get(sessionId)).toBeNull();
  });

  test("an identity that cannot be told still signs the browser out, and says the token may outlive it", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("DELETE", IDENTITY_PATHS.session, { status: 500, fail: new Error("gateway timeout") });

    const res = await h.app.request(...post("/auth/logout", undefined, {}, `${SESSION_COOKIE}=${sessionId}`));

    // Local logout is the security-relevant half, and failing it is worse than a
    // token that lives out its own `exp`. The record goes; the divergence does
    // not, so the caller is told.
    expect(parseSetCookie(res).value).toBe("");
    expect(await h.sessions.get(sessionId)).toBeNull();
    await expectProblem(res, {
      status: 503,
      code: "unavailable",
      detail: "the authentication service could not be reached",
      instance: "/auth/logout",
    });
  });
});

// ------------------------------------------------------------------- GET /auth/me

describe("GET /auth/me", () => {
  test("200 with the user, proxied with the token the store holds", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("GET", IDENTITY_PATHS.me, { status: 200, json: USER });

    const res = await h.app.request(...get("/auth/me", {}, `${SESSION_COOKIE}=${sessionId}`));

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual(USER);

    const [call] = h.identity.callsTo("GET", IDENTITY_PATHS.me);
    expect(call?.token).toBe(TOKEN);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("the response leaks neither the token nor the session id", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("GET", IDENTITY_PATHS.me, { status: 200, json: USER });

    const res = await h.app.request(...get("/auth/me", {}, `${SESSION_COOKIE}=${sessionId}`));
    const body = await res.text();

    expect(body).not.toContain(TOKEN);
    expect(body).not.toContain(sessionId);
  });

  test("no cookie is a 401 and identity is never called", async () => {
    const h = harness();

    const res = await h.app.request(...get("/auth/me"));

    await expectProblem(res, {
      status: 401,
      code: "unauthorized",
      detail: "no session cookie was presented",
      instance: "/auth/me",
    });
    expect(h.identity.calls).toHaveLength(0);
  });

  test("an expired session is a 401 and identity is never called", async () => {
    const h = harness();
    await h.sessions.put("3f2504e0-4f89-41d3-9a0c-0305e82c3301", { token: TOKEN, expiresAt: Date.now() - 1 });

    const res = await h.app.request(
      ...get("/auth/me", {}, `${SESSION_COOKIE}=3f2504e0-4f89-41d3-9a0c-0305e82c3301`),
    );

    await expectProblem(res, {
      status: 401,
      code: "unauthorized",
      detail: "the session is no longer valid",
      instance: "/auth/me",
    });
    expect(h.identity.calls).toHaveLength(0);
  });

  test("a session that is gone clears the cookie, so the browser stops re-sending it", async () => {
    const h = harness();
    await h.sessions.put("3f2504e0-4f89-41d3-9a0c-0305e82c3301", { token: TOKEN, expiresAt: Date.now() - 1 });

    const res = await h.app.request(
      ...get("/auth/me", {}, `${SESSION_COOKIE}=3f2504e0-4f89-41d3-9a0c-0305e82c3301`),
    );

    expect(res.status).toBe(401);
    // Left in place it would be presented on every subsequent request and
    // refused every time, which reads as a signed-out user with a broken page
    // rather than a signed-out user.
    expect(parseSetCookie(res).value).toBe("");
  });

  test("a session identity has withdrawn is a 401, and the record is dropped", async () => {
    // Sign-out-everywhere, or a revoked session, has to take effect at once and
    // not at the next token expiry.
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("GET", IDENTITY_PATHS.me, { status: 401, json: { code: "unauthorized" } });
    h.identity.clear();

    const res = await h.app.request(...get("/auth/me", {}, `${SESSION_COOKIE}=${sessionId}`));

    await expectProblem(res, {
      status: 401,
      code: "unauthorized",
      detail: "the session is no longer valid",
      instance: "/auth/me",
    });
    expect(await h.sessions.get(sessionId)).toBeNull();

    // Second call: nothing left to ask about, so nobody is asked.
    expect((await h.app.request(...get("/auth/me", {}, `${SESSION_COOKIE}=${sessionId}`))).status).toBe(401);
    expect(h.identity.calls).toHaveLength(1);
  });

  test("an identity outage is 503, and the session survives it", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("GET", IDENTITY_PATHS.me, { status: 502, fail: new Error("bad gateway") });

    const res = await h.app.request(...get("/auth/me", {}, `${SESSION_COOKIE}=${sessionId}`));

    await expectProblem(res, {
      status: 503,
      code: "unavailable",
      detail: "the authentication service could not be reached",
      instance: "/auth/me",
    });
    // An outage is not a revocation. Dropping the session here would sign every
    // user out the moment identity hiccups.
    expect(await h.sessions.get(sessionId)).not.toBeNull();
  });

  test("a 200 from identity that is not a user is 503", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.route("GET", IDENTITY_PATHS.me, { status: 200, json: { id: 7 } });

    const res = await h.app.request(...get("/auth/me", {}, `${SESSION_COOKIE}=${sessionId}`));

    expect(res.status).toBe(503);
  });
});

// ------------------------------------------------------------------ CSRF: origin

describe("the same-origin gate on mutating /auth routes", () => {
  test("a cross-origin POST is 403 and identity is never called", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const res = await h.app.request(
      ...post("/auth/login", { email: USER.email, password: "hunter22" }, { origin: "https://evil.example" }),
    );

    await expectProblem(res, {
      status: 403,
      code: "forbidden",
      detail: "this request is not from the same origin",
      instance: "/auth/login",
    });
    // The one thing a 403 has to guarantee: no credential left this process.
    expect(h.identity.calls).toHaveLength(0);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("a valid session cookie does not make a cross-origin POST work", async () => {
    const h = harness();
    const sessionId = await signedIn(h);
    h.identity.clear();

    const res = await h.app.request(
      ...post("/auth/logout", undefined, { "sec-fetch-site": "cross-site" }, `${SESSION_COOKIE}=${sessionId}`),
    );

    expect(res.status).toBe(403);
    // Logout is the one route where a forged cross-site request would be worth
    // something even without a credential.
    expect(await h.sessions.get(sessionId)).not.toBeNull();
    expect(h.identity.calls).toHaveLength(0);
  });

  test("every mutating route is gated", async () => {
    for (const path of ["/auth/register", "/auth/login", "/auth/logout"]) {
      const h = harness();

      const res = await h.app.request(
        ...post(path, { email: USER.email, password: "hunter22" }, { origin: undefined, "sec-fetch-site": undefined }),
      );

      expect(res.status).toBe(403);
      expect(h.identity.calls).toHaveLength(0);
    }
  });

  test("Sec-Fetch-Site: same-origin alone is enough", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const res = await h.app.request(
      ...post("/auth/login", { email: USER.email, password: "hunter22" }, { origin: undefined }),
    );

    expect(res.status).toBe(200);
  });

  test("same-site is refused: a sibling subdomain is not this origin", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    // SameSite=Lax cookies *are* sent to a sibling subdomain, so a subdomain
    // that can post to its parent has something to steal.
    const res = await h.app.request(
      ...post("/auth/login", { email: USER.email, password: "hunter22" }, { "sec-fetch-site": "same-site" }),
    );

    expect(res.status).toBe(403);
  });

  test("none is refused: the UA could not attribute the request to a page", async () => {
    const h = harness();

    const res = await h.app.request(
      ...post("/auth/login", { email: USER.email, password: "hunter22" }, { "sec-fetch-site": "none" }),
    );

    expect(res.status).toBe(403);
  });

  test("a value that is not one of the four is refused, not treated as absent", async () => {
    for (const site of ["same_origin", "sameorigin", "same origin", ""]) {
      const h = harness();

      const res = await h.app.request(
        ...post("/auth/login", { email: USER.email, password: "hunter22" }, { "sec-fetch-site": site, origin: undefined }),
      );

      // Not a value the specification defines, so not a claim this gate can
      // read as same-origin. Refusing is the direction to fail in.
      expect(res.status).toBe(403);
    }
  });

  test("the value is compared case-insensitively, so a UA casing change is not an outage", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    const res = await h.app.request(
      ...post("/auth/login", { email: USER.email, password: "hunter22" }, { "sec-fetch-site": "SAME-ORIGIN" }),
    );

    // Fixed as a token comparison, not a string one: a browser that changes the
    // casing of a header value would otherwise lock every user out of sign-in,
    // and case-folding four known tokens cannot be what an attacker forges.
    expect(res.status).toBe(200);
  });

  test("an Origin naming another host is refused", async () => {
    const h = harness();

    const res = await h.app.request(
      ...post("/auth/login", { email: USER.email, password: "hunter22" }, { "sec-fetch-site": undefined, origin: "https://evil.example" }),
    );

    expect(res.status).toBe(403);
  });

  test("Origin: null is refused", async () => {
    // A sandboxed iframe or a redirect chain. There is no origin to compare.
    const h = harness();

    const res = await h.app.request(
      ...post("/auth/login", { email: USER.email, password: "hunter22" }, { "sec-fetch-site": undefined, origin: "null" }),
    );

    expect(res.status).toBe(403);
  });

  test("neither header is refused: an unstated origin is not a same-origin one", async () => {
    const h = harness();

    const res = await h.app.request(
      ...post("/auth/login", { email: USER.email, password: "hunter22" }, { origin: undefined, "sec-fetch-site": undefined }),
    );

    expect(res.status).toBe(403);
  });

  test("the scheme is not compared, because a TLS-terminating proxy rewrites it", async () => {
    const h = harness();
    loginSucceeds(h.identity);

    // guard sees http:// after the proxy terminates TLS while the browser's
    // Origin is https://. Comparing schemes would 403 every real browser.
    // Comparing hosts is safe: the host is the one the browser addressed the
    // request to, and a cross-site requester cannot choose it.
    const res = await h.app.request(`http://${HOST}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: CONSOLE },
      body: JSON.stringify({ email: USER.email, password: "hunter22" }),
    });

    expect(res.status).toBe(200);
  });

  test("a same-origin GET is not gated: reading needs no CSRF defence", async () => {
    const h = harness();

    const res = await h.app.request(`https://${HOST}/auth/me`);

    // 401 from the missing cookie, not 403 from the gate. Mounting the gate on
    // the /auth/* prefix would have got this wrong.
    expect(res.status).toBe(401);
  });
});

// ------------------------------------------------------------- the app surface

describe("the /auth surface", () => {
  test("an app built with no bff option serves no /auth routes at all", async () => {
    // Nothing to proxy to is not a degraded auth mode. The routes are absent, so
    // a misconfigured deployment is a 404 rather than an endpoint that would
    // have to invent a session.
    const res = await createApp().request(...post("/auth/login", { email: USER.email, password: "hunter22" }));

    expect(res.status).toBe(404);
  });

  test("the probes still answer, and a bff app has no session in /healthz", async () => {
    const h = harness();

    expect((await h.app.request("/healthz")).status).toBe(200);
    expect((await h.app.request("/readyz")).status).toBe(200);
    expect(h.identity.calls).toHaveLength(0);
  });

  test("/auth traffic is rate limited like any other traffic", async () => {
    const identity = fakeIdentity();
    loginSucceeds(identity);
    const app = createApp({
      bff: { identityUrl: IDENTITY_URL, fetch: identity.fetch },
      rateLimit: { limit: 1, windowMs: 60_000 },
    });

    expect((await app.request(...post("/auth/login", { email: USER.email, password: "a" }))).status).toBe(200);
    expect((await app.request(...post("/auth/login", { email: USER.email, password: "a" }))).status).toBe(429);
  });

  test("a malformed identity URL is a startup error, not a 503 on every login", async () => {
    for (const value of ["identity.test:8080", "ftp://identity.test", "http://identity.test/v1", "  "]) {
      expect(() => createBffAuth({ identityUrl: value })).toThrow(RangeError);
    }
  });

  test("a zero timeout is a configuration error, not 'no limit'", async () => {
    for (const timeoutMs of [0, -1, 1.5]) {
      expect(() => createBffAuth({ identityUrl: IDENTITY_URL, timeoutMs })).toThrow(RangeError);
    }
  });
});

// ------------------------------------------------------------------- the probe

describe("identityProbe", () => {
  test("identity's healthz answering 200 is ok", async () => {
    const identity = fakeIdentity();
    identity.route("GET", IDENTITY_PATHS.healthz, { status: 200, json: { status: "ok" } });

    expect(await identityProbe({ identityUrl: IDENTITY_URL, fetch: identity.fetch })()).toBe("ok");
  });

  test("a 500, a rejection and a hang are all unavailable, and none of them throws", async () => {
    const identity = fakeIdentity();
    const probe = identityProbe({ identityUrl: IDENTITY_URL, fetch: identity.fetch, timeoutMs: 25 });

    identity.route("GET", IDENTITY_PATHS.healthz, { status: 500 });
    expect(await probe()).toBe("unavailable");

    identity.route("GET", IDENTITY_PATHS.healthz, { status: 200, fail: new Error("refused") });
    expect(await probe()).toBe("unavailable");

    identity.route("GET", IDENTITY_PATHS.healthz, { status: 200, hang: true });
    expect(await probe()).toBe("unavailable");
  });
});
