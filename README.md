# guard

The cafaye public gateway. It is the only door into a cafaye deployment:
`guard` authenticates callers, limits what they can ask for, and (later)
forwards requests to the service that owns the work.

**Status: v0 has working auth and no routing.** Tokens are verified for real
against identity's published keys; no request is proxied to a service yet, and
rate-limit counters are per process. See [Not built yet](#not-built-yet) before
relying on anything here.

## Endpoints

| Method | Path       | Auth  | Rate limited | v0 behaviour                                          |
| ------ | ---------- | ----- | ------------ | ----------------------------------------------------- |
| GET    | `/healthz` | no    | no           | always `200 {"status":"ok"}` — liveness, touches nothing |
| GET    | `/readyz`  | no    | no           | `200 {"deps":{…}}`, or `503` if a registered probe is down |
| GET    | `/v1/me`   | bearer | yes          | `200` echoing the verified `{sub, scope, claims}`      |

`/v1/me` exists to prove the auth chain end to end and forwards nothing. It is
replaced by routed traffic when the routing packet lands.

The two shapes an error can take, and why, is a **DECISION NEEDED** — see
[Errors](#errors).

## Auth

Bearer JWTs only, verified locally against identity's JWKS. `Authorization:
Bearer <jwt>`; a cookie is not a credential here, and a browser-facing BFF
surface is a later packet.

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

## Errors

Auth failures use **core's error envelope** — RFC 9457 `problem+json` with
cafaye's extensions, as fixed in `core/docs/openapi-conventions.md`:
`type`, `title`, `status`, `detail`, `instance`, `code` and a `trace_id` that
matches the `X-Trace-Id` response header. `code` is one of core's reserved codes:
`unauthorized`, `forbidden`, `unavailable`.

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
curl localhost:8080/readyz
curl localhost:8080/v1/me        # 401: no bearer token
```

Point it at a real identity to get past the 401:

```sh
IDENTITY_ISSUER=https://identity.localhost \
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
- **Cookie sessions / BFF.** API traffic is bearer-only. The browser surface —
  `Secure`/`HttpOnly`/`SameSite` cookies plus a CSRF token — is a different
  surface and a later packet.
- **SSE / streaming pass-through**, **an OpenAPI document and contract tests**
  (see the `DECISION NEEDED` in [cafaye.yml](cafaye.yml)), and **structured
  logging**.

## Layout

```
src/index.ts                 createApp + runtimeOptions + the Bun.serve bootstrap
src/problem.ts               core's error envelope, the one rejection path
src/middleware/jwt.ts        createJwtVerifier — RS256, JWKS cache, scopes
src/middleware/rateLimit.ts  in-memory fixed-window limiter
test/jwksServer.ts           a stand-in identity for the suite (never shipped)
bin/prime                    the gate
Dockerfile                   oven/bun slim, multi-stage; `docker build --target test` runs the suite in the image
```

Conventions live in [AGENTS.md](AGENTS.md); changes are recorded in
[CHANGELOG.md](CHANGELOG.md).

## Licence

MIT.
