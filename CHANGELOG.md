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

### Changed

- `requireJwt` is no longer a stub. Anything downstream of it is authenticated:
  the README's "no request may be treated as authenticated" line is gone with it.
- An identity outage is now `503 unavailable` rather than `401`: a caller whose
  token was fine must not be told to fix their credential because a dependency
  is down.
- `createApp` returns `Hono<AuthEnv>` so handlers get a typed principal, and
  takes an optional `jwt` option. An app built without one serves probes only.

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

[Unreleased]: https://github.com/cafaye/guard/compare/v0.0.0...HEAD
[v0.0.0]: https://github.com/cafaye/guard/releases/tag/v0.0.0
