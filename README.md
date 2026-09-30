# guard

The cafaye public gateway. It is the only door into a cafaye deployment:
`guard` authenticates callers, limits what they can ask for, and (later)
forwards requests to the service that owns the work.

**Status: v0 has working auth, a browser login surface, API keys, and no
routing.** Tokens are verified for real against identity's published keys; a
browser signs in through guard and comes away with a session cookie instead of a
token; a script can hold a scoped, revocable API key; no request is proxied to a
service yet. Rate-limit counters are per process unless `REDIS_URL` names a
shared store, and sessions are always per process. See
[Not built yet](#not-built-yet) before relying on anything here.

## Endpoints

| Method | Path             | Auth           | Rate limited | v0 behaviour                                               |
| ------ | ---------------- | -------------- | ------------ | ---------------------------------------------------------- |
| GET    | `/healthz`       | no             | **never**    | always `200 {"status":"ok"}` — liveness, touches nothing     |
| GET    | `/readyz`        | no             | **never**    | `200 {"deps":{…}}`, or `503` if a registered probe is down   |
| GET    | `/v1/me`         | bearer or key  | yes (`guard-api`) | `200` echoing the verified `{sub, scope, claims}`      |
| POST   | `/auth/register` | same-origin    | yes (`guard-auth-register`) | `201 {id, email}`. No session: a registration is not a login |
| POST   | `/auth/login`    | same-origin    | yes (`guard-auth-login`) | `200 {expires_at}` + the `__Host-bff-session` cookie |
| POST   | `/auth/logout`   | same-origin    | yes (`guard-auth-logout`) | `204`, cookie cleared, identity asked to revoke    |
| GET    | `/auth/me`       | cookie         | yes (`guard-auth`) | `200 {id, email}`, proxied to identity with the stored token |

`/v1/*` is the API surface: bearer tokens and API keys, never a cookie.
`/auth/*` is the browser surface, and a browser never touches the other one — see
[BFF auth flow](#bff-auth-flow).

The two probe endpoints are exempt from the limiter, and the reason is not
tidiness: a throttled probe is an orchestrator that cannot see a healthy process,
and the restart that follows is worse than the traffic it was guarding against.

`/v1/me` exists to prove the auth chain end to end and forwards nothing. It is
replaced by routed traffic when the routing packet lands.

The two shapes an error can take, and why, is a **DECISION NEEDED** — see
[Errors](#errors).

## The HTTP contract

[`openapi/v1.yaml`](openapi/v1.yaml) is guard's OpenAPI 3.1 document, and it
describes the seven operations in the table above and nothing else. It is what a
generated client is built from, so it is held to the router by
[`test/openapiDocument.test.ts`](test/openapiDocument.test.ts), which reads the
document and Hono's own `app.routes` and fails if either describes an operation
the other does not.

Three things about that check are worth knowing before trusting it:

- It compares **method+path pairs**, never counts. A count comparison passes on a
  rename and fails on a pure addition, which is backwards.
- Both readers **raise** rather than under-read, and the check asserts each side
  produced operations at all — two readers that both find nothing agree with each
  other, and a green check over nothing is worse than no check.
- The route set comes from the **program's own definitions**, not from a list
  written out in a test, which is the shape that can only fail for a name
  somebody remembered.

`/v1/*` and `/*` are in neither side's operation set: they are `app.use(…)`
mounts, and Hono records every mount with the method `ALL`. They are excluded as
exact method+path pairs, **not** as a `/v1/` prefix — a route added under `/v1/`
next year is a `GET` and is not covered by that carve-out. `GET /v1/me` is under
that prefix and is in the document, which is the standing proof.

The document's header records **seven departures from
[`core/docs/openapi-conventions.md`](../core/docs/openapi-conventions.md)** as
open decisions rather than resolving them locally. The most consequential is that
`cafaye.yml` still has no `exposes` block: the document the omission was waiting
for now exists, and pointing the platform's `caf gen` at it is the manager's call.

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

## Rate limiting

The limiter is a **sliding window** (GCRA) counting in **one atomic step** behind
a `RateLimitStore` trait with two implementations. Three properties matter and
each has a test that would fail without it.

### Which bucket a request belongs to

The key is derived in one order, and nothing a caller chose is ever in it.

| Order | Bucket key      | Comes from                                                       | Why it is safe                                                                  |
| ----- | --------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| 1     | `account:<id>`  | the account claim of a **verified** JWT, or the account a key names | Only set by the JWT verifier or the API-key gate, after verification.             |
| 2     | `apikey:<id>`   | the id of a key the store looked up                              | An id, never the secret. Two keys are two buckets even from one address.          |
| 3     | `ip:<address>`  | the client address                                                | Only when the deployment says how much of `X-Forwarded-For` to believe.           |
| 4     | `ip:unknown`    | nothing could be established                                      | A named unknown, not a blank key. Groups more callers than necessary, trusts none. |

- **Never a header value.** `X-Account-Id` is chosen by the caller, and a limiter
  keyed on it is not a limiter — it is a way to mint a fresh allowance per
  request. There is no configuration that makes this true instead.
- **Never an unverified token.** The limiter is mounted *after* the auth gates, so
  a request it refuses has no identity to key on. A token that fails verification
  is answered `401` and counted against nothing; the cost of that ordering is that
  a credential-garbage flood is not counted either, which is affordable because a
  rejected token costs no key fetch (the algorithm is read off the header first).
- **The account beats the key.** A caller holding both a token and a key for the
  same account spends one allowance, so a second credential is not a way to double
  your rate. A browser session is not an API caller: `/auth/*` authenticates with
  a cookie and sets no principal, so its traffic is keyed by address and a script
  holding a key can never spend a person's browser budget.
- **`X-Forwarded-For` is read from the right.** `TRUSTED_PROXIES=n` means *n*
  proxies append to the chain, and the address is read at that hop counting from
  the end; everything to the left of it is something the caller wrote. With
  `TRUSTED_PROXIES=0` the header is not read at all. A chain shorter than the
  trusted run falls back to the socket peer, because a bucket that groups too many
  callers is the direction to be wrong in.
- **The counter key is a digest.** `rateLimitKey` produces whatever the verified
  identity contains — an `account_id` claim is whatever identity chose, an IPv6
  address can carry a `%zone` — and a bucket name becomes a Redis key. The
  identity is therefore hashed into the key, which makes an unsafe key impossible
  by construction rather than by a charset somebody remembers, and means a
  `KEYS guard:rl:*` scan does not yield a list of the accounts hitting the edge.

### Why sliding, and why one step

A fixed window hands out `limit` per aligned bucket of time, so `limit` requests
one millisecond before the edge plus `limit` one millisecond after it is 2× the
allowance inside two milliseconds. GCRA spends the allowance continuously instead:
a caller is thought of as owing `tat - now` of time, each request adds
`windowMs / limit` of debt, and time passing repays it a piece at a time. The
boundary case is written out in `rateLimitStore.test.ts` — five requests 1 ms
before the edge and five 1 ms after it, and the second five are all refused.

Counting and reading are **one call** because a read-then-write limiter admits N×
the limit under a burst: every replica reads "4 used, limit 5" and all five write
"5 used". The burst tests fire 200 concurrent requests at a limit of 50 and assert
exactly 50 admitted and 150 refused, through the in-memory store and through the
Redis path, and `rateLimitParity.test.ts` runs one behaviour table through both
implementations and requires byte-identical transcripts.

### What a client is told

There is **no RFC for these fields yet**. The citation is the IETF HTTPAPI working
group's Standards Track draft,
[`draft-ietf-httpapi-ratelimit-headers-11`](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)
(Polli, Martinez Ruiz, Miller; 23 May 2026), which builds on **RFC 9651**
(Structured Field Values for HTTP). The brief cited RFC 9331; that is L4S/ECN and
has nothing to do with rate limiting.

```
RateLimit-Policy: "guard-api";q=600;w=60     # §3: the policy. q = quota, w = window seconds
RateLimit: "guard-api";r=598;t=44            # §4: r = available, t = effective window
RateLimit-Limit: 600                          # the trio the draft dropped in -08,
RateLimit-Remaining: 598                      # which deployed clients and proxies
RateLimit-Reset: 44                           # still parse. Seconds, counting down.
X-RateLimit-Limit: 600                        # this repository's own fields, which
X-RateLimit-Remaining: 598                    # predates the draft. X-RateLimit-Reset
X-RateLimit-Reset: 1784557432104              # is an absolute epoch instant.
Retry-After: 44                               # on a 429 only, in whole seconds
```

`t` is the **effective window** — the seconds within which the advertised quota
may be used (§4.1.2) — so it counts down; the draft's own examples move it (`r=60;
t=58` two seconds into a hundred-a-minute policy). `Retry-After` on a 429 is the
instant *that* request would next be admitted, never zero, because `Retry-After:
0` is an instruction to come straight back into a bucket that cannot open for
another few hundred milliseconds. §7 makes `Retry-After` take precedence when both
are present, which is the order they are meant to be read in.

A 429 is core's error envelope like every other rejection:

```json
{ "type": "https://errors.cafaye.com/rate_limited", "title": "Too many requests",
  "status": 429, "detail": "too many requests for this window",
  "instance": "/v1/me", "code": "rate_limited", "trace_id": "…" }
```

### Per-route allowances

A gateway that gives one number to every route cannot be strict where strictness
is what stops an attack and generous where generosity is what a client needs.

| Policy                | Limit   | Window | Claimed by                        |
| --------------------- | ------- | ------ | --------------------------------- |
| `guard-api`           | 600     | 1 min  | `/v1/*` and anything unclaimed     |
| `guard-auth`          | 60      | 1 min  | any other `/auth/` route           |
| `guard-auth-login`    | 10      | 1 min  | `POST /auth/login`                 |
| `guard-auth-register` | 5       | 1 min  | `POST /auth/register`              |
| `guard-auth-logout`   | 30      | 1 min  | `POST /auth/logout`                |
| `guard-api-keys`      | 60      | 1 min  | `/v1/api-keys`                     |

Longest matching prefix wins, on a path-segment boundary, so `/v1/` never claims
`/v1alpha/`. The **policy name is the unit of accounting**, not the route: it is
half the counter key, so `/auth/login` and `/auth/register` are separate budgets
and a caller brute-forcing logins cannot lock out every legitimate sign-up from
that address. The numbers are a starting point, not a measurement — nothing in
this repository has watched a real caller. `RATE_LIMIT_REQUESTS` and
`RATE_LIMIT_WINDOW_MS` override the general allowance only; the auth-adjacent
entries are code in v0, because a table that is half environment and half code is
a table where lowering `default` is mistaken for having lowered the login limit.

### Where the counters live

| `REDIS_URL` | Store             | Shared across replicas | Survives restart |
| ----------- | ----------------- | ---------------------- | ---------------- |
| unset       | in-memory, per process | **no**           | no               |
| set         | Redis, one GCRA Lua script | yes              | yes              |

**The in-memory store is single-instance only, and that is not a caveat — it is a
different limit.** A caller gets `limit` per window from *each* replica, so N
replicas is an N× allowance, and every bucket is lost on restart. Set `REDIS_URL`
for anything with more than one replica; the URL is parsed at startup so a typo is
a startup error, and the connection is opened on first use so a Redis that is
*down* is not a refusal to boot.

**A store that cannot answer fails OPEN**, and the cost is named rather than
hidden: for as long as the counter store is unreachable, guard applies no limit at
all. Failing closed would hand a Redis outage to every caller as a `429`, which is
the same class of mistake as restarting the process on a dependency blip and much
harder to notice. The `RateLimit-*` headers are left off rather than guessed at —
a client told `RateLimit-Limit: 600` and then never refused is worse off than one
told nothing — and Redis is a registered readiness dependency, so `/readyz` says
`{"deps":{"identity":"ok","redis":"unavailable"}}`.

**The Lua script is executed, in CI.** The default suite drives the Redis path
through a line-for-line transcription of the script (`rateLimitRedis.test.ts`), and
the RESP2 encoder and parser are covered as pure functions — so `bin/prime` needs
no server and no network. A second tier,
`src/middleware/rateLimitRedisLive.test.ts`, runs the same script against a real
`redis-server`; it is gated on `GUARD_REDIS_URL`, and the `redis` job in
`.github/workflows/ci.yml` sets it with `GUARD_REDIS_REQUIRED=true` so a run
cannot pass by quietly skipping it. `TODO(guard-06)` in
`src/middleware/rateLimitRedis.ts` — run it in the *deploy* pipeline — is still
open; CI proves the script, not that a given deployment sets `REDIS_URL`.

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
> `{ "error": …, "message": … }` with `application/json` — the `404` and the
> `500`. Two error shapes in one gateway is a wart, and core says no service
> invents its own error body. The `429` moved onto the envelope with the rate
> limiter that produces it; what is left is the `404` and the `500`, and moving
> them means touching every response, and the envelope's `trace_id` has to match an
> `X-Trace-Id` that exists on *every* response, which is a trace-propagation
> middleware that does not exist yet. Requested: a `guard-0N` that adds trace-id
> propagation and moves `404`/`500` onto the same envelope in one go. Until then,
> read the `Content-Type` to tell the two apart.

The shape is declared once, as `components.schemas.Problem` in
[`openapi/v1.yaml`](openapi/v1.yaml), and every error response in that document
references it — so a client generated from the document gets the envelope rather
than a copy of it, and this section and the document cannot describe two
different things without the reader noticing one of them is out of date. That
document's `Problem.code` enum is the list above and the two extra slugs
`cafaye.yml` records; it deliberately does **not** list `not_found` or
`internal`, because guard produces neither.

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
| `RATE_LIMIT_REQUESTS`    | `600`                       | Requests per window on the general allowance. Integer ≥ 1; `0` is a startup error, not "unlimited". |
| `RATE_LIMIT_WINDOW_MS`   | `60000`                     | Length of that window in milliseconds. Integer ≥ 1. |
| `TRUSTED_PROXIES`        | `0`                         | How many proxies append to `X-Forwarded-For`, and therefore how much of it is believed. `0` believes none of it and keys on the socket peer. |
| `REDIS_URL`              | unset                       | `redis://` or `rediss://` — host and port, no path. Set it and the counters are shared by every replica and survive a restart. Unset and they are this process's memory. |
| `REDIS_PREFIX`           | `guard:rl`                  | Sub-namespace inside guard's own, so two guards or two environments sharing one Redis do not read each other's buckets. |

`IDENTITY_URL` is a second variable for one service on purpose. The issuer is an
https origin in every environment, including the compose stack; the address guard
*dials* is a service name, and inside a container `localhost` is guard itself. So
`docker-compose.yml` sets it explicitly rather than relying on the default.

An empty or whitespace-only variable counts as unset, which is what
`IDENTITY_ISSUER=` in a compose file should mean. A malformed value is a startup
error, never a silent default: `IDENTITY_JWKS_TTL_MS=0` or `=soon` refuses to
boot rather than quietly fetching identity on every request.

`REDIS_URL` is validated at startup and connected lazily. The split is
deliberate: `REDIS_URL=redis//redis` is a mistake worth refusing to boot over,
while a Redis that is *down* is somebody else's outage, and a gateway that will
not start without its counter store has turned it into its own.

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
bin/prime                        # frozen install, typecheck, then the suite (the gate)
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

## CI

`.github/workflows/ci.yml` calls kit's reusable workflow and adds four jobs of
its own:

```yaml
uses: cafaye/kit/.github/workflows/ci.reusable.yml@master
with:
  language: bun
  working-dir: .
  versions: '{"bun":"1.3.12"}'
```

| Job          | What it is                                                        | Why kit cannot own it |
| ------------ | ----------------------------------------------------------------- | --------------------- |
| `ci`         | kit's `bun` job: frozen install, typecheck, test                   | — it *is* the shared half |
| `prime`      | runs `bin/prime` itself, then `git diff --exit-code -- bun.lock`     | the gate is guard's command, and the lockfile check needs an install to have run |
| `redis`      | the live Redis tier, against a real `redis:7.4.1-alpine`            | guard's counter store is guard's dependency |
| `manifest`   | `cafaye.yml` against core's fetched manifest schema                 | it reaches into `cafaye/core` |
| `image`      | hadolint, `docker build --target test`, the test files it ran, `docker compose build` | kit's lint tier does not cover Dockerfiles |

### The image runs the same tests you do

`docker build --target test` is a gate, and a gate that runs a subset is a claim
rather than a check. It used to: the test stage copied `src`, `test` and
`openapi`, and `pins.test.ts` sits at the repository root, so the image ran **392
tests across 15 files** where a host run ran **399 across 16**. The seven missing
were the test asserting that the Bun pin in `package.json`, `mise.toml`, the
Dockerfile and compose all say the same number — the check that would have noticed
the image disagreeing with the repository was the one test the image did not run.
The build was green.

A test file the image does not have does not fail, it is simply not executed, so
nothing in the build output says so. Two checks close that, and they close
different halves of it:

| Where | What it reads | What it catches |
| ----- | ------------- | --------------- |
| `test/dockerStage.test.ts`, in the suite | the Dockerfile's `COPY` list | a test file the image never asked for |
| the `image` job in CI | the built image | a `.dockerignore` rule dropping a directory out of a `COPY src ./src` |

The first runs everywhere the suite runs — `bin/prime`, kit's workflow, the image
— so a new test file fails the local gate until the list names it. `COPY . .`
would make it vacuous (a whole-context copy is always a superset) and would put the
doubles in `test/` one careless edit from the runtime stage, so the list stays
explicit. The second exists because the first reads the Dockerfile and so is blind
to `.dockerignore`: buildkit copies the rest of an excluded directory and the
build stays green. The suite emits every test file it discovered, and CI diffs
that set against `find`.

It compares **file counts, not test counts**, on purpose. The live Redis tier
skips in-image by design, so the pass count legitimately differs from a host run
with Redis; the file count cannot.

**The live tier, and why it is a separate job.** `bin/prime` needs no server: it
drives the Redis path through a JavaScript transcription of GCRA_LUA.
`src/middleware/rateLimitRedisLive.test.ts` runs the actual script against a real
`redis-server`, and it is environment-gated, so without the `redis` job it skips
and the run is green without having run it. The job sets `GUARD_REDIS_REQUIRED`,
which turns "no Redis" from a skip into a failure, and a second step parses the
summary and fails on `0 pass` or any skip — `bun test` exits 0 on a fully skipped
file, so a green step is not by itself evidence that the tier ran.

To run it locally:

```sh
docker run -d --rm -p 6379:6379 redis:7.4.1-alpine
GUARD_REDIS_URL=redis://127.0.0.1:6379 GUARD_REDIS_REQUIRED=true \
  bun test src/middleware/rateLimitRedisLive.test.ts
```

**The pin.** Bun 1.3.12 is stated in `package.json` (`packageManager`),
`mise.toml`, the Dockerfile's `ARG BUN_VERSION`, compose's build arg and this
workflow's `versions` input. `pins.test.ts` asserts all of them agree, so a bump
in one fails the gate instead of quietly testing one runtime and shipping another.
`engines.bun` is deliberately a floor (`>=1.3.0`), not a pin.

## Not built yet

Each line is a packet, not a plan. The stubs that stand in for them are marked in
the source with the packet that replaces them.

- **Routing.** No request is proxied to a service. The service registry that
  decides where a path goes does not exist yet, and `/v1/me` is a placeholder
  for the surface that will replace it.
- **The live Redis tier does not run inside the image.** `docker build --target
  test` has no `redis-server` and no way to reach one: buildkit refuses
  `--network=host`, a sidecar is not addressable from a `RUN`, and installing one
  into the stage is 30 MB and 15 seconds to obtain a check the `redis` job already
  forces. The tier is instead forced where a server can exist — the `redis` CI job,
  against a pinned `redis:7.4.1-alpine`. The gap is bounded rather than hidden: the
  `image` job compares **test files**, not test counts, precisely so the 14 skips
  this causes are expected and a genuinely missing test file is not. If a future
  packet wants the image to execute the script, the honest form is a
  `redis-server` in the test stage, and it changes what the image produces.
- **The Redis script is executed in CI, not in a deployment.** `REDIS_URL`
  selects a real shared store, and the GCRA Lua now runs against a real
  `redis-server` on every push (`redis` job; see
  [Where the counters live](#where-the-counters-live)). What is still unbuilt is
  the *deploy* half: `TODO(guard-06)` in `src/middleware/rateLimitRedis.ts` is to
  run the script where `REDIS_URL` is actually configured, so a deployment that
  sets it is checked against the store it will really use. CI proves the script;
  nothing yet proves a given deployment points at a working Redis.
- **Thirteen test files ship in the runtime image.** The Dockerfile copies `src`
  into the runtime stage, and thirteen `src/**/*.test.ts` come with it. They are
  inert — nothing imports them, and `bun:test` is a runtime builtin rather than a
  dependency the production tree installs — so this is about what the image
  contains, not about what it can do. Removing them means copying the tree with
  the tests excluded, which changes what the image produces, so it is a packet
  rather than a line. `test/dockerStage.test.ts` asserts the runtime stage names
  no `test/` tree and no whole context, which is the half that matters: the
  identity and JWKS doubles under `test/` do not ship.
- **A shared API-key store.** Keys are issued, hashed, scoped and revoked, and a
  revoked key is dead on the next request — but the store is a `Map` in one
  process, so a key issued on one replica does not exist on the next and a
  deployment behind a load balancer authenticates intermittently. `ApiKeyStore` is
  the seam; `TODO(guard-07)`. Deliberately absent rather than written wrongly.
- **No endpoint issues a key.** `createApiKeyAuth` can mint and revoke one, and a
  key authenticates on any route a token does, but nothing in guard *hands* one
  out: issuing a credential is a control-plane action that wants an authenticated
  account, an audit trail and a rate limit of its own (`guard-api-keys` is already
  in the table for it), and that route is not one this packet was asked to invent.
  What is missing is the caller, not the capability.
- **A trustworthy client key still needs an edge proxy.** The address key is only
  as good as `TRUSTED_PROXIES`, and at the default of `0` guard keys on the socket
  peer — so every caller behind one NAT shares one bucket. The old behaviour,
  keying on the first `X-Forwarded-For` hop, was worse: the caller chose it. Both
  are honest now; neither is a substitute for a proxy that overwrites the header.
- **Token lifetime.** guard verifies `exp` and `nbf` but enforces no ceiling on
  how long a token may live. core's conventions cap access tokens at 15 minutes;
  whether the edge enforces that or trusts identity to mint short-lived ones is
  a later decision.
- **ES256.** RS256 only, per this packet's contract. See the DECISION NEEDED in
  [cafaye.yml](cafaye.yml).
- **One error shape.** `404` and `500` still answer `{ error, message }`; the
  `429` moved onto the envelope with the limiter that writes it. See
  [Errors](#errors).
- **Shared sessions.** The session store is a `Map` in one process, so a
  browser's session dies with the replica it signed in on and is lost on restart.
  The `SessionStore` interface is the seam; Redis-backed sessions are the deploy
  packet, marked `TODO(guard-06)` in the source. A CSRF *token* is also not here —
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
  brute-force control at the edge, and on `/auth/*` it keys on the client address
  because a browser session has no principal — so a login endpoint is exactly
  where `TRUSTED_PROXIES` being wrong matters most, and a lockout at the edge is a
  later decision.
- **SSE / streaming pass-through**, **contract tests against this document**
  (`caf contract lint` validating real responses against `openapi/v1.yaml`), and
  **structured logging**. The OpenAPI document itself has shipped — see
  [The HTTP contract](#the-http-contract) — so the `DECISION NEEDED` in
  [cafaye.yml](cafaye.yml) is down to the `exposes` block alone.

## Layout

```
src/index.ts                 createApp + runtimeOptions + the Bun.serve bootstrap
src/problem.ts               core's error envelope, the one rejection path
src/probe.ts                 what a readiness probe is
src/middleware/jwt.ts        createJwtVerifier — RS256, JWKS cache, scopes
src/middleware/limitKey.ts   which bucket a request is: account > api key > address
src/middleware/limits.ts     the per-route allowance table
src/middleware/rateLimit.ts  the limiter: key, policy, headers, 429, fail-open
src/middleware/rateLimitTypes.ts   the RateLimitStore contract
src/middleware/rateLimitStore.ts   GCRA in memory, per process
src/middleware/rateLimitRedis.ts   GCRA in Redis, one Lua script, plus RESP2
src/middleware/apiKey.ts     API keys: issue, authenticate, revoke
src/middleware/assert.ts     configuration checks, one RangeError each
src/bff/auth.ts              the /auth surface: identity calls, the cookie, the origin gate
src/bff/session.ts           SessionStore + the in-memory v0 implementation
test/fakeIdentity.ts         a stand-in for identity's auth API (never shipped)
test/jwksServer.ts           a stand-in for identity's JWKS (never shipped)
test/limitTable.ts           a one-number limit table, for tests
test/openapiPaths.ts         reads openapi/v1.yaml and Hono's app.routes (never shipped)
test/openapiPaths.test.ts    the reader's own contract: it raises rather than under-reads
test/openapiDocument.test.ts the document held to the router, in both directions
test/dockerStage.ts          reads a Dockerfile's stages and COPY chain (never shipped)
test/dockerStage.test.ts     the test stage's file set held to the repository's
openapi/v1.yaml              the HTTP contract, and the open decisions in its header
bin/prime                    the gate
Dockerfile                   oven/bun slim, multi-stage; `docker build --target test` runs the suite in the image
```

Conventions live in [AGENTS.md](AGENTS.md); changes are recorded in
[CHANGELOG.md](CHANGELOG.md).

## Licence

MIT.
