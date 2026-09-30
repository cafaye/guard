# AGENTS.md

Conventions for `guard`, the cafaye public gateway. Read this before changing
anything; the house rules in `moon/PLAN.md` §1 and §3 apply on top of it.

## What this repository is

`guard`, TypeScript on Bun >= 1.3, one HTTP process. It is the only door into a
cafaye deployment: it authenticates callers, limits what they can ask for, and
(forwards requests) to the service that owns the work. The contracts are owned by
`cafaye/core`; the manifest in `cafaye.yml` is how the other tools find this
service.

v0 is **structure only**. There is no routing to a real service, no token
verification, and no shared rate-limit state. The README's "Not built yet" list
is the source of truth for what this repository does not claim.

## Layout

```
src/index.ts            the app factory (createApp) + the Bun.serve bootstrap
src/middleware/jwt.ts   requireJwt — STUB, presence check only
src/middleware/rateLimit.ts  in-memory fixed-window limiter
bin/prime               the gate: bun install && bun test
```

`createApp` is the only thing the tests import, and it must stay importable
without opening a socket — the `Bun.serve` call is behind `import.meta.main`.
Configuration arrives as an argument (`AppOptions`), never as a module-level
global read from the environment, so a test can build two differently-configured
apps in one process.

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

**Stubs stay honest, and say so in their own file.** `jwt.ts` is a presence
check, and it must never grow a token parse that *looks* like verification: a
half-check is worse than an obvious stub, because a caller will believe a token
was checked when nothing was. Every stub carries a `TODO(guard-0N)` naming the
packet that replaces it, and the README lists it as not built. A packet that is
not written yet is absent, not a fake that looks finished.

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
programming error, not "unlimited". The one exception is *absent*: an app
built with no `rateLimit` option runs unlimited, which is the honest v0 default.

**Deps are `hono` and nothing else.** Reasoning in
[README.md](README.md#why-hono-and-bun). No JWT library, no Redis client, no
logger, no test framework beyond `bun test`, no dependency without a cause
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
bin/prime          # bun install && bun test
bun run typecheck  # tsc --noEmit, must print nothing
docker compose build   # the test stage runs the suite; a red suite fails the build
```

All three gates before a commit lands.

`mise trust` gates the typecheck rather than being housekeeping: mise refuses to
read an untrusted config, and `bun run typecheck` reaches `node` to launch
`tsc`, so an untrusted `mise.toml` fails the gate for a reason that has nothing
to do with the code. Run it once per clone before the first gate.

## Adding an endpoint

1. Decide whether it is liveness, readiness, or traffic. Only traffic is
   authenticated and rate limited.
2. Tests first: status code, JSON shape, `Content-Type`, the anonymous case, and
   the throttled case if it is traffic.
3. Handlers return JSON errors in the shape the suite already pins —
   `{ "error": …, "message": … }` — because the two middlewares and `notFound`
   all use it.
4. If it needs a dependency, add a `Probe` to the record `createApp` builds.
   Never a bespoke health path.
5. Add the row to the README endpoint table, add a `CHANGELOG.md` entry, and
   re-run the three gates.
