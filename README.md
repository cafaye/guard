# guard

The cafaye public gateway. It is the only door into a cafaye deployment:
`guard` authenticates callers, limits what they can ask for, and (later)
forwards requests to the service that owns the work.

**Status: v0 has working auth, a browser login surface, and no routing.** Tokens
are verified for real against identity's published keys; a browser signs in
through guard and comes away with a session cookie instead of a token; no
request is proxied to a service yet, and rate-limit counters and sessions are
per process. See [Not built yet](#not-built-yet) before relying on anything here.

## Endpoints

| Method | Path             | Auth        | Rate limited | v0 behaviour                                               |
| ------ | ---------------- | ----------- | ------------ | ---------------------------------------------------------- |
| GET    | `/healthz`       | no          | no           | always `200 {"status":"ok"}` — liveness, touches nothing     |
| GET    | `/readyz`        | no          | no           | `200 {"deps":{…}}`, or `503` if a registered probe is down   |
| GET    | `/v1/me`         | bearer       | yes          | `200` echoing the verified `{sub, scope, claims}`            |
| POST   | `/auth/register` | same-origin | yes          | `201 {id, email}`. No session: a registration is not a login |
| POST   | `/auth/login`    | same-origin | yes          | `200 {expires_at}` + the `__Host-bff-session` cookie         |
| POST   | `/auth/logout`   | same-origin | yes          | `204`, cookie cleared, identity asked to revoke              |
| GET    | `/auth/me`       | cookie      | yes          | `200 {id, email}`, proxied to identity with the stored token  |

`/v1/*` is the API surface: bearer tokens, never a cookie. `/auth/*` is the
browser surface, and a browser never touches the other one — see
[BFF auth flow](#bff-auth-flow).

`/v1/me` exists to prove the auth chain end to end and forwards nothing. It is
replaced by routed traffic when the routing packet lands.

The two shapes an error can take, and why, is a **DECISION NEEDED** — see
[Errors](#errors).

## Auth

Two surfaces, two credentials, and they do not cross.

**API traffic** (`/v1/*`) is bearer JWTs only, verified locally against
identity's JWKS. `Authorization: Bearer <jwt>`; a cookie is not a credential
there.

**Browser traffic** (`/auth/*`) is the BFF: a `__Host-bff-session` cookie and
nothing else. identity's token never reaches the page. See
[BFF auth flow](#bff-auth-flow).

- **Algorithm: RS256, and nothing else.** The algorithm is guard's decision, not
  the token's, and it is checked before any key is fetched — so an `alg: none` or
  HS256 token cannot make guard call identity. core's conventions also allow
  ES256; see the DECISION NEEDED in [cafaye.yml](cafaye.yml).
- **Keys:** `{IDENTITY_ISSUER}/.well-known/jwks.json`. `IDENTITY_ISSUER` is the
  **issuer-only base URL** (e.g. `https://identity.localhost`); guard appends the
  fixed well-known path itself. The path is not part of the variable, and a
  trailing slash is fine.
- **Caching:** the key set is held in memory for `IDENTITY_JWKS_TTL_MS`
  (default `300000`). A token naming a `kid` that is not in the cached set
  triggers **one** forced refresh per cache window and is then refused — enough
  to pick up a rotation, not enough to let a caller aim every request at
  identity. The TTL is also the revocation window: a key identity withdraws keeps
  verifying until the cache expires.
- **Claims checked:** `iss` (the issuer), `aud` (guard's client id), `exp`,
  `nbf`, and a non-empty `sub`. `scope` is read when present as a
  space-separated string and split into a set; absent means no scopes, never all
  of them.
- **Rejections** — a bad signature, an expired token, a wrong `iss` or `aud`, an
  `nbf` in the future, a malformed token, or a `kid` identity does not publish
  is `401`. A token without the scope a route needs is `403`. Identity's key set
  being unreachable, unparseable, or slow is `503`, because that is the
  platform's outage and not the caller's credential.
- The reason a request was refused is fixed text chosen per case. The underlying
  error — a host, a port, a status code — goes to the log and never to an
  unauthenticated caller.

Handlers read the verified principal off the context, and a scope gate mounts
after the auth gate:

```ts
const jwt = createJwtVerifier({ issuer: "https://identity.localhost", audience: "guard" });

app.use("/v1/*", jwt.requireJwt);
app.get("/v1/invoices", jwt.requireScope("billing.read"), (c) => c.json(c.get("principal")));
```

## BFF auth flow

A browser talks to guard and to nothing else. It never sees identity's endpoints,
never holds identity's token, and never names its own session: it holds a session
id out of a cookie guard minted, and guard swaps that id for the token when a
request needs one. A token in a page is a token a cross-site script can read; a
session id in an `HttpOnly` cookie is not.

### Sign in

```
browser                    guard                          identity
  |                          |                                |
  |-- POST /auth/login ----->|                                |
  |   Origin: console…       |                                |
  |   {email, password}      |                                |
  |                          |-- POST /v1/session ----------->|
  |                          |<-- 200 {token, expires_at} ----|
  |                          |                                |
  |                          | store: sessionId -> token      |
  |<-- 200 {expires_at} -----|                                |
  |    Set-Cookie: __Host-bff-session=<uuid>; Secure; HttpOnly;|
  |                 SameSite=Lax; Path=/                       |
```

The body carries no token. Echoing it would hand the page the long-lived
credential the `HttpOnly` cookie exists to keep away from it.

### Use the session

```
  |-- GET /auth/me ---------->|   cookie: __Host-bff-session=<uuid>
  |                          |   store: sessionId -> token
  |                          |-- GET /v1/me  (Bearer <token>) ->|
  |                          |<-- 200 {id, email} -------------|
  |<-- 200 {id, email} -------|   only {id, email} is returned
```

### Sign out

```
  |-- POST /auth/logout ----->|   cookie, same-origin headers
  |                          |   drop the store record, clear the cookie
  |                          |-- DELETE /v1/session (Bearer) -->|
  |                          |<-- 204 -------------------------|
  |<-- 204, Set-Cookie: __Host-bff-session=; Max-Age=0 ---------|
```

### The rules, and why each one is here

- **The cookie is `__Host-bff-session`, `Secure`, `HttpOnly`, `SameSite=Lax`,
  `Path=/`.** The `__Host-` prefix is a contract the browser enforces — Secure,
  `Path=/`, no `Domain` — which makes the cookie impossible for a subdomain or a
  plain-HTTP sibling origin to set or overwrite. That is the cookie-fixation
  vector a plain `session` cookie leaves open. `Lax` and not `Strict`, because a
  `Strict` cookie is not sent on the top-level navigation a user follows
  straight after signing in. The deletion repeats every attribute: a browser
  matches a cookie to delete on name, domain and path, and one mismatch leaves
  the original in place — the bug that makes "sign out" appear to do nothing.
- **The session id is `crypto.randomUUID()`, minted by guard, never accepted from
  the caller.** Fixation needs an id the attacker knows in advance.
- **The store is a `SessionStore` — three methods — and the v0 implementation
  is a `Map`.** Expiry is the store's business, because a record the store knows
  is dead is not a record. Redis-backed sessions are the deploy packet; see
  [Not built yet](#not-built-yet).
- **Mutating `/auth/*` routes require a provably same-origin request.** Either
  `Sec-Fetch-Site: same-origin` — set by the user agent, not by the page — or an
  `Origin` whose host is the one the request was addressed to. `same-site` is
  refused because a `Lax` cookie *is* sent to a sibling subdomain, so a subdomain
  that can post to its parent has something to spend. A request with neither
  header is refused: every browser sends one, and a client that sends neither has
  no ambient credential to abuse but is also not *provably* same-origin. `curl`
  and the test suite state their origin. `GET /auth/me` is not gated — reading
  needs no CSRF defence, and putting the gate on the `/auth/*` prefix would
  demand an `Origin` header from it.
- **The origin is compared by host, not by scheme.** A TLS-terminating proxy
  rewrites the scheme guard sees while the browser's header still says `https`,
  and comparing it would 403 every real browser. The host is the one the browser
  addressed the request to, and a cross-site requester cannot choose it.
- **Only the statuses identity documents for a route are mapped.** A `200` to
  `POST /v1/users`, or a `423` on a login identity did not lock, is a `503` rather
  than a guess: a guess here is how a lockout turns into a `401` and a retry loop
  the caller owns. A `422` keeps core's `errors[]`, because a sign-up form
  renders it. A `423` keeps its `Retry-After`.
- **A request body is capped at 4 KiB, at the reader.** `request.text()` is the
  whole body in memory, so an unauthenticated caller would otherwise choose how
  much of the edge one request holds. A `Content-Length` over the cap is refused
  from the header alone; a body that only *becomes* too large is refused at the
  chunk that crosses it, and the stream is cancelled rather than drained. 4 KiB is
  identity's own cap, so nothing is lost by refusing it here.
- **A login or a register that is refused sets no cookie.** And a login whose
  token, expiry or `expires_at` is missing, unparseable, or already in the past
  is a `503` with nothing stored: the alternative is a cookie the store will
  refuse on the very next request, which is a login that reports success and then
  signs the user straight out.
- **An identity `401` on `GET /auth/me` drops the store record.** Sign-out
  everywhere has to take effect at once, not at the token's `exp`. An identity
  *outage* does not drop it: that is not a revocation, and treating it as one
  would sign every user out whenever identity hiccups.
- **Logout clears locally first and then asks identity to revoke.** Failing to
  sign a browser out is worse than a token that outlives its revocation until
  `exp`, so the local session always goes; a `503` is the caller's evidence that
  the remote one may not have. A `401` or `404` from identity is a `204` — a
  token it has already forgotten is the end state that was asked for — as is a
  cookie the store has lost, which is what a restart leaves behind.
- **One call to identity is bounded.** The signal cancels a real fetch and a race
  bounds the handler if the fetch ignores it: the difference between a request
  that fails and a process that stops answering.
- **`/auth/*` is rate limited like any other traffic**, including the requests the
  origin gate refuses, because a cross-site POST that costs a request to reject
  is a cross-site POST worth rejecting.
- **identity is a readiness dependency.** `runtimeOptions` registers the probe,
  so a configured `/readyz` reports `{"deps":{"identity":"unavailable"}}` when the
  auth surface cannot work.

**No new dependency:** the cookie attributes come from `hono/cookie`, which is
part of `hono`.

```sh
# The flow, by hand. Every mutating call needs to state its origin.
curl -i -X POST localhost:8080/auth/login -H 'origin: https://console.cafaye.com' \
  -H 'content-type: application/json' -d '{"email":"ada@cafaye.com","password":"…"}'

curl -i localhost:8080/auth/me --cookie '__Host-bff-session=<the uuid from Set-Cookie>'
```

## Errors

Auth failures use **core's error envelope** — RFC 9457 `problem+json` with
cafaye's extensions, as fixed in `core/docs/openapi-conventions.md`:
`type`, `title`, `status`, `detail`, `instance`, `code` and a `trace_id` that
matches the `X-Trace-Id` response header. `code` is one of core's reserved codes
where one exists — `unauthorized`, `forbidden`, `unavailable`, `conflict`,
`validation_failed` — plus `invalid_json` (400), `account_locked` (423) and
`payload_too_large` (413), which are the slugs identity already answers with and
which core does not name. One vocabulary across the platform beats a
guard-private synonym for the same failure; recorded as a DECISION NEEDED in
[cafaye.yml](cafaye.yml). `errors[]` appears on a `422` and nowhere else, as core
scopes it.

The `/auth` routes map each identity refusal onto that envelope: a `401` login is
`401`, a `422` registration keeps its `errors[]`, a `423` keeps its
`Retry-After`, and a `409` is `409`. The `detail` is always a fixed string per
case, and never identity's own body — it can carry a field name, a host or a
reason that means nothing outside identity.

> **DECISION NEEDED (guard).** The rest of the surface still answers
> `{ "error": …, "message": … }` with `application/json` — the `404`, the `429`
> and the `500`. Two error shapes in one gateway is a wart, and core says no
> service invents its own error body. It was left alone deliberately: migrating
> them means touching every response, and the envelope's `trace_id` has to match
> an `X-Trace-Id` that exists on *every* response, which is a trace-propagation
> middleware that does not exist yet. Requested: a `guard-0N` that adds trace-id
> propagation and moves `404`/`429`/`500` onto the same envelope in one go.
> Until then, read the `Content-Type` to tell the two apart.

## Configuration

`createApp` takes its configuration as an argument and reads nothing from the
environment, so a test can build two differently configured apps in one process.
`runtimeOptions` is the only place the environment is read, and it is what the
`Bun.serve` bootstrap passes in.

| Variable                 | Default                     | Meaning                                                            |
| ------------------------ | --------------------------- | ------------------------------------------------------------------ |
| `PORT`                   | `8080`                      | Listen port.                                                        |
| `IDENTITY_ISSUER`        | `https://identity.localhost` | Issuer-only base URL. The `/.well-known/jwks.json` path is appended by guard, not written here. Also the expected `iss`. |
| `IDENTITY_JWKS_URL`      | derived from the issuer     | Full key-set URL, for a key set served somewhere other than the issuer's own well-known path. |
| `IDENTITY_JWKS_TTL_MS`   | `300000`                    | How long a fetched key set is reused, in milliseconds.              |
| `GUARD_CLIENT_ID`        | `guard`                     | The `aud` guard accepts — guard's own client id.                   |
| `IDENTITY_URL`           | `http://localhost:8080`     | identity's base URL for the `/auth` calls: where a session is *requested*, as against `IDENTITY_ISSUER`, which is where tokens are *verified*. http(s), no path. |

`IDENTITY_URL` is a second variable for one service on purpose. The issuer is an
https origin in every environment, including the compose stack; the address guard
*dials* is a service name, and inside a container `localhost` is guard itself. So
`docker-compose.yml` sets it explicitly rather than relying on the default.

An empty or whitespace-only variable counts as unset, which is what
`IDENTITY_ISSUER=` in a compose file should mean. A malformed value is a startup
error, never a silent default: `IDENTITY_JWKS_TTL_MS=0` or `=soon` refuses to
boot rather than quietly fetching identity on every request.

## Why Hono and Bun

**Hono** because it is Web-standard `Request`/`Response` with no Node callback
API to unwrap, so the same handlers, the same tests, and the same middleware run
unchanged on Bun, on workers, and on whatever runtime a service outgrows; and it
is small enough to read in one sitting, which matters for the component every
request passes through.

**Bun** because it runs TypeScript directly — the gateway ships no build step,
so there is no compile artifact that can disagree with the source that was
reviewed — and because `bun test` gives the table-driven, fake-timer tests this
service needs with no test-runner dependency to adopt or to keep patched.

**jose** because verifying a signature against a published key set is the one
place in this repository where hand-rolling would be unforgivable: RSA
verification, the algorithm-confusion attacks, and the key-set parsing are
security-critical code that has to be right the first time and audited by people
who are not us. `jose` is the JOSE implementation the JavaScript ecosystem
audits, it is Web-standard `crypto` rather than a native module, and it is a
dependency with no transitive tree. Everything else in this service is a
framework choice; this one is a correctness choice.

## Running it

```sh
bin/prime                        # bun install && bun test  (the gate)
bun run src/index.ts             # http://localhost:8080
curl localhost:8080/healthz
curl localhost:8080/v1/me        # 401: no bearer token
curl localhost:8080/readyz       # {"deps":{"identity":"unavailable"}}: no identity to ask
```

Point it at a real identity to get past either refusal:

```sh
IDENTITY_ISSUER=https://identity.localhost \
IDENTITY_URL=http://identity.localhost:8080 \
  bun run src/index.ts
```

With Docker:

```sh
docker compose up -d --build
curl localhost:8080/healthz
```

`mise.toml` pins the toolchain. If you use mise, run this once per clone
**before** the gates:

```sh
mise trust && mise install
```

`mise trust` is not optional housekeeping: mise refuses to read a config file it
has not been told to trust, and `bun run typecheck` reaches `node` (to launch
`tsc`), so an untrusted `mise.toml` fails the typecheck gate even though nothing
in this repository is wrong. Without mise, install Bun 1.3.x and Node 22
yourself and everything below works unchanged.

## Not built yet

Each line is a packet, not a plan. The stubs that stand in for them are marked in
the source with the packet that replaces them.

- **Routing.** No request is proxied to a service. The service registry that
  decides where a path goes does not exist yet, and `/v1/me` is a placeholder
  for the surface that will replace it.
- **Shared rate limits.** The limiter is in-memory and per process: a client gets
  its allowance from *each* replica, and counts reset on restart. Redis-backed
  counting is a later packet.
- **A trustworthy client key.** The limiter keys on the first
  `X-Forwarded-For` hop, which the caller chooses, so a client can mint a fresh
  allowance per request until an edge proxy overwrites that header. It is
  recorded as a known hole, not hidden behind a default.
- **Token lifetime.** guard verifies `exp` and `nbf` but enforces no ceiling on
  how long a token may live. core's conventions cap access tokens at 15 minutes;
  whether the edge enforces that or trusts identity to mint short-lived ones is
  a later decision.
- **ES256.** RS256 only, per this packet's contract. See the DECISION NEEDED in
  [cafaye.yml](cafaye.yml).
- **One error shape.** `404`, `429` and `500` still answer `{ error, message }`.
  See [Errors](#errors).
- **Shared sessions.** The session store is a `Map` in one process, so a
  browser's session dies with the replica it signed in on and is lost on restart.
  The `SessionStore` interface is the seam; Redis-backed sessions are the deploy
  packet, marked `TODO(guard-04)` in the source. A CSRF *token* is also not here —
  the origin gate is the defence, and a double-submit token would be a second
  thing to get right for the same protection.
- **OIDC at the edge.** No redirect flow, no authorization-code exchange, no
  `/.well-known` discovery for a browser. A browser signs in with an email and a
  password through guard today; the OIDC packets replace that with a redirect to
  identity, at which point the CSRF state parameter is identity's to issue and
  guard's to check.
- **Password rules, lockout and enumeration** are identity's, not guard's. guard
  forwards the body untouched and maps what comes back: a `423` with its
  `Retry-After`, a `401` with one fixed sentence. Rate limiting is the only
  brute-force control at the edge, and it keys on the untrustworthy client header
  above — so a login endpoint in front of guard is exactly where that hole
  matters, and a lockout at the edge is a later decision.
- **SSE / streaming pass-through**, **an OpenAPI document and contract tests**
  (see the `DECISION NEEDED` in [cafaye.yml](cafaye.yml)), and **structured
  logging**.

## Layout

```
src/index.ts                 createApp + runtimeOptions + the Bun.serve bootstrap
src/problem.ts               core's error envelope, the one rejection path
src/probe.ts                 what a readiness probe is
src/middleware/jwt.ts        createJwtVerifier — RS256, JWKS cache, scopes
src/middleware/rateLimit.ts  in-memory fixed-window limiter
src/bff/auth.ts              the /auth surface: identity calls, the cookie, the origin gate
src/bff/session.ts           SessionStore + the in-memory v0 implementation
test/fakeIdentity.ts         a stand-in for identity's auth API (never shipped)
test/jwksServer.ts           a stand-in for identity's JWKS (never shipped)
bin/prime                    the gate
Dockerfile                   oven/bun slim, multi-stage; `docker build --target test` runs the suite in the image
```

Conventions live in [AGENTS.md](AGENTS.md); changes are recorded in
[CHANGELOG.md](CHANGELOG.md).

## Licence

MIT.
