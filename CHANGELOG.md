# Changelog

All notable changes to `guard` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). `core`'s
mini-semver grammar (`^`, `~`, `>=`, exact) is what `cafaye.yml` uses; npm
dependency versions follow npm's own rules.

## [Unreleased]

### Added

- App factory `createApp`, exported for tests and the only import the suite
  makes. Importing the module never opens a socket; the `Bun.serve` bootstrap
  is behind `import.meta.main`.
- `GET /healthz` — unconditional `200 {"status":"ok"}`. Liveness never touches a
  dependency.
- `GET /readyz` — `200 {"deps":{…}}`, or `503` naming the dependencies that are
  not ok. A probe that throws, rejects or answers with anything but `"ok"` counts
  as `unavailable`; v0 registers no probes, so it is unconditionally ready.
- `rateLimit` middleware — in-memory fixed-window limiter with wall-clock
  aligned windows, `X-RateLimit-Limit` / `-Remaining` / `-Reset` on allowed and
  rejected requests alike, and `Retry-After` on a 429. Invalid `limit` or
  `windowMs` throws at construction.
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
  from a caller. `TODO(guard-04)`: Redis.
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

- `404`, `429` and `500` still answer `{ "error": …, "message": … }` with
  `application/json`, while auth failures use core's `problem+json`. Two shapes in
  one gateway is a wart, left deliberately: the envelope's `trace_id` has to match
  an `X-Trace-Id` that exists on every response, which is a trace-propagation
  middleware that does not exist yet. DECISION NEEDED in the README.
- RS256 only, per this packet's contract, where core's conventions also allow
  ES256; and the space-separated `scope` claim, where core's conventions call it
  `scopes`. DECISION NEEDED in `cafaye.yml`.
- No token lifetime ceiling. `exp` and `nbf` are checked; how long a token may
  live is not.
- Sessions are per process and per restart: a browser signed in on a replica that
  goes away is signed out, and a deploy signs everybody out. The `SessionStore`
  interface is the seam; Redis is `TODO(guard-04)`.
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
