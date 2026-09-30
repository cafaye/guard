# Changelog

All notable changes to `guard` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). `core`'s
mini-semver grammar (`^`, `~`, `>=`, exact) is what `cafaye.yml` uses; npm
dependency versions follow npm's own rules.

## [Unreleased]

### Fixed

- **One Redis error reply no longer wedges the connection for the life of the
  process.** `connectRedis`'s reader caught every `parseReply` failure, consumed
  no bytes and resolved no waiter, so an `-ERR` was re-parsed on every later chunk
  and every later command on that connection timed out. Because `lazyRedis` caches
  a connection and a counter store that cannot answer fails **open**, a gateway
  that saw one `-ERR` applied no rate limit at all until it restarted — with
  `/readyz` reporting `redis: unavailable` and nothing in the log saying why. An
  error reply is part of RESP, not a desync: Redis sends one deliberately and
  answers the next command normally, so `RedisReplyError` now carries the bytes it
  used and the reader consumes them and fails exactly one command. `parseReply`'s
  contract is unchanged — still an `Error`, still throws. Found by executing the
  GCRA script against a real server, which nothing had done before.

### Added

- **CI, calling kit's reusable workflow.**
  `.github/workflows/ci.yml` calls
  `cafaye/kit/.github/workflows/ci.reusable.yml@master` with `language: bun`, and
  adds four jobs kit cannot own: `prime` (runs `bin/prime` itself and guards
  `bun.lock`), `redis` (a real `redis:7.4.1-alpine` for the live tier), `manifest`
  (validates `cafaye.yml` against core's fetched schema) and `image` (hadolint,
  `docker build --target test`, `docker compose build`).
- **The GCRA Lua is executed, in CI.** `rateLimitRedisLive.test.ts` runs the real
  script against a real `redis-server`; `bin/prime` still needs no server. The
  tier is gated on `GUARD_REDIS_URL`, and `GUARD_REDIS_REQUIRED=true` plus a
  summary check turn a skip into a failure — `bun test` exits 0 on a fully skipped
  file, so a green run is not by itself evidence the tier ran. It found the
  connection wedge above, and a difference the transcription had hidden: Redis
  returns a Lua number truncated toward zero, so `resetAt` and `retryAt` come back
  whole while the in-memory store carries fractions.
- **`packageManager: "bun@1.3.12"`**, and `pins.test.ts` asserting that the pin
  agrees across `package.json`, `mise.toml`, `Dockerfile`, `docker-compose.yml`
  and the workflow. `engines.bun` stays a floor rather than a pin. The pin existed
  only in `mise.toml`, which a contributor without mise never reads, and the
  comment above it claimed an agreement nothing checked. `pins.test.ts` also caught
  `bun.lock` recording the workspace name as `guard-worker-guard-01` — a worktree
  name from packet guard-01, committed because a lockfile is not a file anyone
  opens.
- **`bin/prime` is kit's bun template**: frozen install and typecheck before test,
  so the local gate and CI's are the same bytes rather than two that can disagree.

- **Sliding-window rate limiting.** GCRA in one atomic step, replacing the
  fixed-window counter. A fixed window hands out `limit` per aligned bucket, so
  `limit` requests one millisecond before the edge plus `limit` one millisecond
  after it is 2× the allowance inside two milliseconds; the boundary case is
  written out and asserted in both directions.
- **`RateLimitStore`, with two implementations.** `memoryRateLimitStore` is
  per-process and says so in its own source, in the README and in the compose
  notes — N replicas of it is an N× limit. `redisRateLimitStore` counts in
  Redis with one self-contained Lua script (a read-then-write pair is what admits
  N× the limit under a burst), keeps its keys under `guard:rl:<prefix>:` and
  expires its own. `REDIS_URL` selects it; the URL is validated at startup and the
  connection opens on first use, so a typo refuses to boot and an outage does not.
  `rateLimitParity.test.ts` runs one behaviour table through both and requires
  byte-identical transcripts, so the trait is proven rather than asserted. No test
  in the default gate touches Redis or the network: the Redis path is driven by a
  transcription of the script, and the RESP2 encoder and parser are tested as pure
  functions. The script itself is executed against a real server by
  `rateLimitRedisLive.test.ts`, in CI only.
- **Key derivation in one order: account → API key → address.**
  `src/middleware/limitKey.ts` builds the bucket key from the *verified* principal,
  the id of a key the store looked up, and the client address, and never from a
  header value or an unverified token. Each tier is prefixed so an account id that
  equals an address cannot share a bucket, and the no-identity case is a named
  `ip:unknown` rather than a blank key. The account beats the key, so holding both
  is not a way to double one's rate.
- **`X-Forwarded-For` is read from the right, and only as far as the operator
  says.** `TRUSTED_PROXIES` is how many proxies append to the chain, and the
  address is taken at that hop counting from the end; with the default of `0` the
  header is not read at all and the socket peer is used. A chain shorter than the
  trusted run falls back to the peer, because a bucket that groups too many callers
  is the direction to be wrong in. This replaces keying on the first
  `X-Forwarded-For` hop, which the caller chose.
- **`RateLimit-*` response headers**, on allowed and refused requests alike:
  `RateLimit-Policy` and `RateLimit` as RFC 9651 structured fields per
  `draft-ietf-httpapi-ratelimit-headers-11` (§3 and §4 — there is no RFC for these
  fields yet, and the brief's RFC 9331 is L4S), the `RateLimit-Limit` /
  `-Remaining` / `-Reset` trio the same draft dropped in -08 and deployed clients
  still parse, and this repository's own `X-RateLimit-*`, whose `-Reset` is an
  absolute epoch instant. `t` is the effective window per §4.1.2, so it counts
  down rather than restating `w`. `Retry-After` on a 429 is the instant that
  request would next be admitted, never zero.
- **A per-route limit table** (`src/middleware/limits.ts`) with the policy name as
  the unit of accounting: it is half the counter key, so `/auth/login` (10/min),
  `/auth/register` (5/min) and the general API surface (600/min) are separate
  budgets and a caller brute-forcing logins cannot lock out every legitimate
  sign-up from that address. Longest matching prefix wins, on a path-segment
  boundary. `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_MS` override the general
  allowance.
- **API keys** (`src/middleware/apiKey.ts`): `Authorization: ApiKey <secret>`,
  accepted on any route a token is. Only the SHA-256 is stored, only twelve
  characters are ever shown, the secret exists exactly once at issue and cannot be
  printed again, and `find` is the only lookup so a revoked key is dead on the very
  next request rather than being returned with a flag. A key sets the same
  `principal` a token does, so there is one scope gate in the repository rather
  than two that could disagree. `TODO(guard-07)`: the store is per process.
- **The counter store is a readiness dependency.** `REDIS_URL` registers
  `{"deps":{"redis":…}}` from the same connection the store uses, so `/readyz`
  cannot report a store the limiter is not counting in.
- App factory `createApp`, exported for tests and the only import the suite
  makes. Importing the module never opens a socket; the `Bun.serve` bootstrap
  is behind `import.meta.main`.
- `GET /healthz` — unconditional `200 {"status":"ok"}`. Liveness never touches a
  dependency.
- `GET /readyz` — `200 {"deps":{…}}`, or `503` naming the dependencies that are
  not ok. A probe that throws, rejects or answers with anything but `"ok"` counts
  as `unavailable`.
- JSON `404` for unknown routes and a flat JSON `500` for unhandled handler
  errors, with the detail logged rather than returned.
- Rate limiting skips both probe endpoints.
- `Dockerfile` (oven/bun slim, multi-stage, tests gate the image),
  `docker-compose.yml` (the service only), `bin/prime`, `mise.toml`, `AGENTS.md`
  and this changelog.
- `cafaye.yml` against `core`'s frozen manifest schema, with a
  `DECISION NEEDED` for the `exposes` block that needs a manager-owned OpenAPI
  document.
- `jose` as a dependency, and real JWT verification in place of the presence
  check. RS256 only, verified against identity's JWKS at
  `{IDENTITY_ISSUER}/.well-known/jwks.json`, with `iss`, `aud`, `exp`, `nbf` and
  a non-empty `sub` checked. The algorithm is guard's decision, pinned in code and
  read from the header before any key is fetched, so `alg: none` and HS256 are
  refused without a network call.
- `createJwtVerifier` — `requireJwt` mounts on a path and puts
  `{ sub, scope, claims }` on the context; `requireScope("billing.read")` answers
  `403` for a verified caller without the scope, and `401` when it is mounted
  with no auth in front of it.
- A JWKS cache in the verifier: in memory, `300000` ms by default and
  configurable, with a fetch timeout so a hanging identity cannot hang the edge.
  An unknown `kid` buys exactly one forced refresh per cache window and is then
  refused, which is enough to follow a rotation and not enough to let a caller
  aim requests at identity. A failed fetch leaves the last good key set in place.
- `src/problem.ts` — core's error envelope (RFC 9457 `problem+json` with cafaye's
  extensions) and the single path every rejection takes. `401`, `403` and `503`
  carry `type`, `title`, `status`, `detail`, `instance`, `code`, and a `trace_id`
  that matches the `X-Trace-Id` response header. The underlying failure goes to
  the log, never to the caller.
- `GET /v1/me` — the demo route that proves the chain is wired: `200` echoing the
  verified principal, mounted behind `requireJwt` on `/v1/*`, rate limited, and
  absent entirely when no issuer is configured.
- `runtimeOptions` — the only place the environment is read: `IDENTITY_ISSUER`
  (issuer-only base URL, default `https://identity.localhost`),
  `IDENTITY_JWKS_URL`, `IDENTITY_JWKS_TTL_MS` and `GUARD_CLIENT_ID`. A malformed
  value is a startup error; an empty one is unset.
- `test/jwksServer.ts` — a stand-in identity serving a real JWKS from real RSA
  keys, so the suite tests verification rather than a mock of it. The Dockerfile
  copies it into the test stage only.
- The browser surface: `POST /auth/register`, `POST /auth/login`,
  `POST /auth/logout` and `GET /auth/me` in `src/bff/auth.ts`. guard proxies each
  to identity's `/v1/users`, `/v1/session` and `/v1/me` over an injectable
  `fetch`, and maps the answers onto core's `problem+json` envelope. No new
  dependency: the cookie attributes come from `hono/cookie`.
- `__Host-bff-session`, `Secure` / `HttpOnly` / `SameSite=Lax` / `Path=/`, set on
  login and cleared on logout with every attribute repeated. A login answers
  `{expires_at}` and no token: the page gets a session id, and identity's token
  stays in guard.
- `SessionStore` — `get` / `put` / `delete`, with expiry as the store's business —
  and `memorySessionStore`, a `Map` for v0 that drops a record on the read that
  finds it expired and sweeps expired ones once the map passes its bound. A
  session id is `crypto.randomUUID()`, minted on every login and never accepted
  from a caller. `TODO(guard-07)`: Redis.
- A same-origin gate on the three mutating `/auth` routes, mounted per route
  rather than on the prefix. `Sec-Fetch-Site: same-origin`, or an `Origin` whose
  host is the one the request was addressed to, or `403` — including
  `same-site`, `none`, `Origin: null` and a request stating neither. Both
  headers have to agree when both are present. `GET /auth/me` is not gated.
- `identityProbe` — identity's `/healthz`, bounded, never throwing — registered
  by `runtimeOptions`, so a configured `/readyz` names identity instead of
  reporting ready for an auth surface that cannot work. `Probe` and
  `ProbeStatus` moved to `src/probe.ts` so a module can offer a probe without
  importing the app factory that consumes it; `src/index.ts` re-exports both.
- `IDENTITY_URL` (default `http://localhost:8080`) — where the `/auth` calls are
  sent, as against `IDENTITY_ISSUER`, which is where tokens are verified. http(s)
  and no path; anything else is a startup error.
- `test/fakeIdentity.ts` — a programmable stand-in for identity's auth API,
  recording every call including the `Authorization` header, which is what lets
  the suite assert that the browser's cookie is never identity's token and that
  logout revokes the token the store is holding. Test stage only.

### Changed

- The `429` is core's `problem+json` envelope with `code: "rate_limited"`, like
  every other rejection, instead of `{"error":"rate_limited","message":…}`. The
  `X-RateLimit-Reset` absolute-instant convention is kept, and `X-RateLimit-Limit`
  and `X-RateLimit-Remaining` are sent beside it.
- A counter store that cannot answer now fails **open**, with the cost named in
  the source and the README: for as long as it is unreachable guard applies no
  limit. Failing closed would hand a Redis outage to every caller as a `429`. The
  `RateLimit-*` headers are left off rather than guessed at, and the store is a
  readiness probe.
- The limiter is mounted **after** the auth gates, because the bucket is keyed on
  the strongest identity the request has and that is only known once something has
  proved who is asking. The cost is stated rather than hidden: a request the auth
  gate refuses is never counted, because an unverified token must not become a
  rate-limit key.
- `AppOptions.rateLimit` is now `{limits, store, trustedProxies, now}` rather than
  `{limit, windowMs}`, so a deployment can ship a per-route table and a shared
  store. An app built with no `rateLimit` option still runs unlimited, which is the
  honest v0 default; `rateLimit: {}` takes the shipped table.
- `Principal` gained an optional `accountId`, read once from the verified
  `account_id` claim. A token with no such claim is its own account and the
  rate-limit key falls back to `sub`.

- `requireJwt` is no longer a stub. Anything downstream of it is authenticated:
  the README's "no request may be treated as authenticated" line is gone with it.
- An identity outage is now `503 unavailable` rather than `401`: a caller whose
  token was fine must not be told to fix their credential because a dependency
  is down.
- `createApp` returns `Hono<AuthEnv>` so handlers get a typed principal, and
  takes optional `jwt` and `bff` options. An app built without them serves probes
  only: no issuer means nothing to verify a token against, and no identity means
  no session to mint.
- `problem` gained the codes the browser surface has to produce — `invalid_json`
  (400), `conflict` (409), `payload_too_large` (413), `validation_failed` (422)
  and `account_locked` (423) — and an optional `errors[]`, rendered on a 422 and
  nowhere else as core scopes it. `invalid_json`, `payload_too_large` and
  `account_locked` are identity's slugs for failures core does not name;
  DECISION NEEDED in `cafaye.yml`.
- A request body is read through a 4 KiB cap instead of `request.text()`, so an
  anonymous caller cannot choose how much of the edge one request buffers. A
  `Content-Length` over the cap is refused without a read; a body that only
  becomes too large is refused at the chunk that crosses it and the stream is
  cancelled.

### Known gaps

- `404` and `500` still answer `{ "error": …, "message": … }` with
  `application/json`, while everything else uses core's `problem+json`. Two shapes
  in one gateway is a wart, left deliberately: the envelope's `trace_id` has to
  match an `X-Trace-Id` that exists on every response, which is a trace-propagation
  middleware that does not exist yet. The `429` moved onto the envelope with the
  limiter that writes it. DECISION NEEDED in the README.
- The in-memory rate-limit store is single-instance only: a caller gets its
  allowance from *each* replica and counts reset on restart. `REDIS_URL` fixes it
  and the store is behind a trait, but the GCRA Lua has never been executed against
  a real `redis-server` — the client half is tested, the script body is reviewed.
  `TODO(guard-06)`.
- API keys are issued, hashed, scoped and revocable, and a key authenticates on
  any route a token does, but nothing hands one out: minting a credential is a
  control-plane action that wants an authenticated account and an audit trail. The
  store is also per process, so a key issued on one replica is invisible on the
  next. `TODO(guard-07)`.
- The address key is only as good as `TRUSTED_PROXIES`, and at the default of `0`
  every caller behind one NAT shares a bucket. A proxy that overwrites
  `X-Forwarded-For` is what makes it a real client key.
- RS256 only, per this packet's contract, where core's conventions also allow
  ES256; and the space-separated `scope` claim, where core's conventions call it
  `scopes`. DECISION NEEDED in `cafaye.yml`.
- No token lifetime ceiling. `exp` and `nbf` are checked; how long a token may
  live is not.
- Sessions are per process and per restart: a browser signed in on a replica that
  goes away is signed out, and a deploy signs everybody out. The `SessionStore`
  interface is the seam; Redis is `TODO(guard-07)`.
- `GET /auth/me` clears the session cookie when the record is gone or identity
  has withdrawn the session, so a browser stops presenting a cookie that can
  never work again.
- The origin gate refuses a mutating `/auth` request that states no origin at
  all, which includes every non-browser client until it sets `Origin`. That is the
  strict reading, and it is deliberate: the gate refuses what it cannot prove.
  A double-submit CSRF token, for clients that cannot set headers, is a later
  packet alongside the OIDC redirects.
- `/readyz` on a configured deployment now depends on identity. A browser surface
  that cannot mint a session is a gateway that should not be taking traffic, and
  liveness — which is what a restart acts on — is untouched.

[Unreleased]: https://github.com/cafaye/guard/compare/v0.0.0...HEAD
[v0.0.0]: https://github.com/cafaye/guard/releases/tag/v0.0.0
