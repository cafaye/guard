# guard

The cafaye public gateway. It is the only door into a cafaye deployment:
`guard` authenticates callers, limits what they can ask for, and (later)
forwards requests to the service that owns the work.

**Status: v0 is structure only.** There is no routing to a real service, no token
verification, and no shared rate-limit state. See [Not built yet](#not-built-yet)
before relying on anything here.

## Endpoints

| Method | Path       | Auth | Rate limited | v0 behaviour                                            |
| ------ | ---------- | ---- | ------------ | ------------------------------------------------------- |
| GET    | `/healthz` | no   | no           | always `200 {"status":"ok"}` — liveness, touches nothing |
| GET    | `/readyz`  | no   | no           | `200 {"deps":{…}}`, or `503` if a registered probe is down |

Errors are JSON in one shape everywhere: `{ "error": …, "message": … }`. An
unknown route is `404 not_found`; an unhandled handler error is
`500 internal_error` with the detail in the log, not in the response.

Both probe endpoints are deliberately exempt from rate limiting — see
[AGENTS.md](AGENTS.md).

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

## Running it

```sh
bin/prime                        # bun install && bun test  (the gate)
bun run src/index.ts             # http://localhost:8080
curl localhost:8080/healthz
curl localhost:8080/readyz
```

With Docker:

```sh
docker compose up -d --build
curl localhost:8080/healthz
```

`PORT` is the only environment variable; it defaults to `8080`.

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

- **Token verification.** `requireJwt` checks that an `Authorization` header is
  present and returns `401` without one. It does not parse or verify anything.
  Real JWKS verification against `identity` is a later packet, and until it
  lands, no request may be treated as authenticated.
- **Routing.** No request is proxied to a service. The service registry that
  decides where a path goes does not exist yet.
- **Shared rate limits.** The limiter is in-memory and per process: a client gets
  its allowance from *each* replica, and counts reset on restart. Redis-backed
  counting is a later packet.
- **A trustworthy client key.** The limiter keys on the first
  `X-Forwarded-For` hop, which the caller chooses, so a client can mint a fresh
  allowance per request until an edge proxy overwrites that header. It is
  recorded as a known hole, not hidden behind a default.
- **SSE / streaming pass-through**, **an OpenAPI document and contract tests**
  (see the `DECISION NEEDED` in [cafaye.yml](cafaye.yml)), and **structured
  logging**.

## Layout

```
src/index.ts                 createApp (the app factory) + the Bun.serve bootstrap
src/middleware/jwt.ts        requireJwt — STUB, presence check only
src/middleware/rateLimit.ts  in-memory fixed-window limiter
bin/prime                    the gate
Dockerfile                   oven/bun slim, multi-stage; the test stage gates the build
```

Conventions live in [AGENTS.md](AGENTS.md); changes are recorded in
[CHANGELOG.md](CHANGELOG.md).

## Licence

MIT.
