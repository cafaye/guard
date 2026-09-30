# AGENTS.md

Conventions for `guard`, the cafaye public gateway. Read this before changing
anything; the house rules in `moon/PLAN.md` §1 and §3 apply on top of it.

## What this repository is

`guard`, TypeScript on Bun >= 1.3, one HTTP process. It is the only door into a
cafaye deployment: it authenticates callers, limits what they can ask for, and
(forwards requests) to the service that owns the work. The contracts are owned by
`cafaye/core`; the manifest in `cafaye.yml` is how the other tools find this
service.

v0 terminates real auth — RS256 tokens verified against identity's JWKS — and
routes nothing. The README's "Not built yet" list is the source of truth for what
this repository does not claim.

## Layout

```
src/index.ts            the app factory (createApp), env parsing, Bun.serve bootstrap
src/problem.ts          core's error envelope — the one rejection path
src/middleware/jwt.ts   createJwtVerifier — JWKS cache, RS256, requireScope
src/middleware/rateLimit.ts  in-memory fixed-window limiter
test/jwksServer.ts      a stand-in identity for the suite; the image never gets it
bin/prime               the gate: bun install && bun test
```

`createApp` is the only thing the tests import, and it must stay importable
without opening a socket — the `Bun.serve` call is behind `import.meta.main`.
Configuration arrives as an argument (`AppOptions`), never as a module-level
global read from the environment, so a test can build two differently-configured
apps in one process. `runtimeOptions` is the single place the environment is
read.

## Rules

**Tests first.** Write the case, watch it fail, then implement until green
(PLAN.md §3). Every handler change asserts the status code *and* the JSON body
*and* the `Content-Type` — `/readyz` returning 200 with the wrong shape is a
failure, not a pass.

**Liveness never touches a dependency.** `/healthz` is unconditional and
`/readyz` is the only endpoint that may fail because something else is down. A
database or identity outage must not get the process restarted out from under
in-flight requests. Keep the split, and keep both endpoints exempt from rate
limiting: a throttled probe is an orchestrator that cannot see a healthy
process, and the restart that follows is worse than the traffic it was guarding.

**A probe that fails is `unavailable`, not an exception.** A dependency that
throws, rejects, hangs, or answers with anything but `"ok"` is one unavailable
dependency. None of them may take the process down. Readiness reports which
dependency failed by name; the underlying error goes to the log, never to an
unauthenticated caller — an error message can carry a host, a port or a query.

**The token never chooses how it is checked.** The algorithm is pinned in
`middleware/jwt.ts` and the protected header is read before any key is fetched,
so an `alg: none` or HS256 token costs no network call and never reaches a
verifier. The accepted algorithms are one constant, never something a token can
widen and never a per-request option.

**A dependency outage is `503`, not `401`.** If identity's key set cannot be
fetched, the caller's credential was not the problem, and a 401 would send them
to fix something that is fine. `401` means "this token is not acceptable";
`503` means "we cannot tell".

**Stubs stay honest, and say so in their own file.** A stub must never grow a
token parse that *looks* like verification: a half-check is worse than an
obvious stub, because a caller will believe a token was checked when nothing was.
Every stub carries a `TODO(guard-0N)` naming the packet that replaces it, and the
README lists it as not built. A packet that is not written yet is absent, not a
fake that looks finished.

**A refresh on the hot path needs a reason and a budget.** The JWKS cache is the
only reason guard talks to identity at all, and it is bounded twice: a cached set
is reused for its TTL, and a `kid` that is not in it buys **one** forced refresh
per cache window. A rule a caller can trigger per request is an amplifier aimed
at a dependency, not a fallback.

**Rate-limit counters are per process.** The limiter is in-memory, so a client
gets `limit` per window from *each* replica and the counts reset on restart.
That is acceptable for v0 and is stated in the source. Do not describe it as a
platform-wide limit, and do not add Redis without a packet that says so.

**Windows are aligned to the wall clock, not to the first request.** A client
must not be able to stretch its window by spacing requests out, and every client
should share one reset instant. `X-RateLimit-Reset` is the absolute epoch
millisecond the current window ends — a fixed instant, not "one window from
this request". There is a test for exactly that distinction.

**Invalid config is an error, not a fallback.** `rateLimit` validates `limit` and
`windowMs` at construction and throws a `RangeError`; a limit of `0` is a
programming error, not "unlimited". `createJwtVerifier` does the same for the
issuer, the audience, the key-set URL and both durations, and `runtimeOptions`
does it for the environment. The one exception is *absent*: an app built with no
`rateLimit` option runs unlimited, which is the honest v0 default, and an app
built with no `jwt` option serves probes only.

**Deps are `hono`, `jose` and nothing else.** Reasoning in
[README.md](README.md#why-hono-and-bun). `jose` earns its place because signature
verification is not code to hand-write; there is still no Redis client, no
logger, no test framework beyond `bun test`, and no dependency without a cause
stated in review.

**Comments say why.** Explain the decision and the constraint, not the
mechanism. A comment restating the line below it is noise.

**`cafaye.yml` follows core's frozen schema.** It is `additionalProperties:
false`, so a field core does not define is a validation failure, not a comment.
`exposes` is missing on purpose and the reason is a `DECISION NEEDED` callout in
the file: filling it in needs an OpenAPI document, and specs are manager-owned.

## Gates

```sh
mise trust && mise install   # once per clone, if you use mise — see below
bin/prime                    # bun install && bun test
bun run typecheck            # tsc --noEmit, must print nothing
docker build --target test . # the suite inside the image, the same tree CI builds
docker compose build         # the runtime image itself
```

All of them before a commit lands.

`mise trust` gates the typecheck rather than being housekeeping: mise refuses to
read an untrusted config, and `bun run typecheck` reaches `node` to launch
`tsc`, so an untrusted `mise.toml` fails the gate for a reason that has nothing
to do with the code. Run it once per clone before the first gate.

## Adding an endpoint

1. Decide whether it is liveness, readiness, or traffic. Only traffic is
   authenticated and rate limited.
2. Tests first: status code, JSON shape, `Content-Type`, the anonymous case, and
   the throttled case if it is traffic. A rejection asserts the whole envelope,
   not just the status.
3. Errors go through `problem()` — core's `problem+json` envelope — with a
   `detail` that is a fixed string per case. The v0 `{ "error": …, "message": … }`
   shape survives only on `404`, `429` and `500`, and moving those is a packet
   (see the DECISION NEEDED in the README). Do not add a third shape.
4. If it needs a dependency, add a `Probe` to the record `createApp` builds.
   Never a bespoke health path.
5. Under `/v1/*` the auth gate is already mounted; add `requireScope(...)` after
   it rather than re-checking the token, and mount it on the route, not the
   prefix, so one scoped route does not lock out the rest.
6. Add the row to the README endpoint table, add a `CHANGELOG.md` entry, and
   re-run the three gates.
