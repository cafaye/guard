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
src/probe.ts            what a readiness probe is, so a module can offer one
src/middleware/jwt.ts   createJwtVerifier — JWKS cache, RS256, requireScope
src/middleware/limitKey.ts  which bucket a request is: account > api key > address
src/middleware/limits.ts     the per-route allowance table
src/middleware/rateLimit.ts  the limiter — key, policy, headers, 429, fail-open
src/middleware/rateLimitTypes.ts   the RateLimitStore contract
src/middleware/rateLimitStore.ts   GCRA in memory, per process
src/middleware/rateLimitRedis.ts   GCRA in Redis, one Lua script, plus RESP2
src/middleware/apiKey.ts     API keys — issue, authenticate, revoke
src/middleware/assert.ts     configuration checks, one RangeError each
src/bff/auth.ts         the /auth surface — identity calls, the cookie, the origin gate
src/bff/session.ts      SessionStore + the in-memory v0 implementation
test/fakeIdentity.ts    a stand-in for identity's auth API; the image never gets it
test/jwksServer.ts      a stand-in for identity's JWKS; the image never gets it
test/limitTable.ts      a one-number limit table, for tests
pins.test.ts            the bun pin, asserted across every file that states it
bin/prime               the gate: frozen install, typecheck, bun test
.github/workflows/ci.yml   kit's reusable workflow, plus the four jobs it cannot own
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

**The bucket is the strongest identity the request has, and no weaker.** The key
is derived in one order — verified account id, then API key id, then client
address — in `middleware/limitKey.ts`, and never from a header value or an
unverified token. The limiter is mounted *after* the auth gates for that reason,
so a token that does not verify is answered 401 and counted against nothing. Keep
the ordering, and keep the consequence visible: a credential-garbage flood is not
counted either, which is affordable only because a rejected token costs no key
fetch.

**A bucket name is not a place to put caller input.** The identity is digested
into the counter key before it reaches a store, because an `account_id` claim is
whatever identity chose to put there and a bucket name becomes a Redis key. A key
that trips a store's charset check is not a loud failure: the store throws, the
middleware fails open, and the limiter is silently off in the deployment that has
one.

**Count and read in one step, or it is not a limiter.** `RateLimitStore` has one
method and no `peek`, because a read-then-write counter admits N× the limit under
a burst. Any new implementation is proved by `rateLimitParity.test.ts`, which
runs one behaviour table through every implementation and requires identical
transcripts. `bin/prime` touches neither Redis nor the network: the Redis path is
driven by a transcription of its Lua and its transport is tested as pure
functions. The script *itself* is executed by `rateLimitRedisLive.test.ts`
against a real `redis-server`, in the `redis` CI job only — see below.

**In-memory is single-instance only, and is never called a platform limit.** A
caller gets `limit` per window from *each* replica, so N replicas is an N× limit,
and every bucket is lost on restart. `REDIS_URL` selects the shared store; the
truth is in the source, the README and the manifest's DECISION NEEDED, and it
stays in all three.

**The window slides; there is no aligned edge.** GCRA spends the allowance
continuously, because a fixed window hands out 2× the limit across its boundary in
two milliseconds. Do not reintroduce wall-clock-aligned buckets, and do not report
`remaining` as a countdown to a fixed edge: under a sliding window a caller
pacing itself at exactly its allowance holds a constant remaining, and a
countdown would promise burst room the limiter then refuses.

**A counter store that cannot answer fails OPEN.** The cost is named in the source
and the README: for as long as it is unreachable, guard applies no limit. Failing
closed would hand a Redis outage to every caller as a 429. The `RateLimit-*`
headers are left off rather than guessed at, and the store is a readiness probe —
which is what makes the gap visible instead of silent.

**Invalid config is an error, not a fallback.** `rateLimit` validates `limit`,
`windowMs` and `trustedProxies` at construction and throws a `RangeError`; a limit
of `0` is a programming error, not "unlimited". `limitTable` validates every
entry, `createApiKeyAuth` validates the account and the scopes of every key it
issues, `createJwtVerifier` does the same for the issuer, the audience, the
key-set URL and both durations, and `runtimeOptions` does it for the environment.
The one exception is *absent*: an app built with no `rateLimit` option runs
unlimited, which is the honest v0 default, and an app built with no `jwt` option
serves probes only.

**Deps are `hono`, `jose` and nothing else.** Reasoning in
[README.md](README.md#why-hono-and-bun). `jose` earns its place because signature
verification is not code to hand-write; there is still no Redis *client*
dependency — `rateLimitRedis.ts` is forty lines of RESP2 and a transport port, and
that is deliberate — no logger, no test framework beyond `bun test`, and no
dependency without a cause stated in review. `node:crypto` is a runtime builtin,
not a package: SHA-256 for an API key and for a bucket digest, and
`crypto.getRandomValues` for the key itself.

**Comments say why.** Explain the decision and the constraint, not the
mechanism. A comment restating the line below it is noise.

**`cafaye.yml` follows core's frozen schema.** It is `additionalProperties:
false`, so a field core does not define is a validation failure, not a comment.
`exposes` is missing on purpose and the reason is a `DECISION NEEDED` callout in
the file: filling it in needs an OpenAPI document, and specs are manager-owned.

## Gates

```sh
mise trust && mise install   # once per clone, if you use mise — see below
bin/prime                    # frozen install, typecheck, bun test
bun run typecheck            # tsc --noEmit, must print nothing
docker build --target test . # the suite inside the image, the same tree CI builds
docker compose build         # the runtime image itself
```

All of them before a commit lands.

`mise trust` gates the typecheck rather than being housekeeping: mise refuses to
read an untrusted config, and `bun run typecheck` reaches `node` to launch
`tsc`, so an untrusted `mise.toml` fails the gate for a reason that has nothing
to do with the code. Run it once per clone before the first gate.

**An environment-gated tier that skips is a green run that verified nothing.**
`rateLimitRedisLive.test.ts` needs a real `redis-server`, so it skips when
`GUARD_REDIS_URL` is unset — and `bun test` exits 0 on a fully skipped file. Two
mechanisms stop that from reading as a pass, and a new gated tier needs both:

- `GUARD_REDIS_REQUIRED=true` makes the tier throw at module load when the URL is
  unset, rather than skip.
- The `redis` job parses the summary and fails on `0 pass` or on any skip.

Set the environment and prove the count. A tier added without both is a tier
nobody will notice is not running.

**CI runs `bin/prime`, not a CI-only variant.** kit's `bun` job runs the same
*steps* from kit's copy of the conventions, and the `prime` job runs guard's own
command, so the two cannot drift into disagreeing about what the gate is. The
`git diff --exit-code -- bun.lock` that follows it is the check that survives a
future edit dropping `--frozen-lockfile`: a plain `bun install` resolves a
different tree and the run stays green while doing it.

## Adding an endpoint

1. Decide whether it is liveness, readiness, or traffic. Only traffic is
   authenticated and rate limited.
2. Tests first: status code, JSON shape, `Content-Type`, the anonymous case, and
   the throttled case if it is traffic. A rejection asserts the whole envelope,
   not just the status.
3. Errors go through `problem()` — core's `problem+json` envelope — with a
   `detail` that is a fixed string per case. The v0 `{ "error": …, "message": … }`
   shape survives only on `404` and `500`, and moving those is a packet (see the
   DECISION NEEDED in the README). Do not add a third shape.
4. If it needs a dependency, add a `Probe` to the record `createApp` builds.
   Never a bespoke health path.
5. Under `/v1/*` the auth gate is already mounted; add `requireScope(...)` after
   it rather than re-checking the token, and mount it on the route, not the
   prefix, so one scoped route does not lock out the rest.
6. If it needs its own allowance, add a row to `DEFAULT_LIMIT_TABLE` and a test
   for that row. The policy name is the unit of accounting, so a new entry is a
   new budget and a new bucket, not a second number under an existing one.
7. **Register the route after the limiter.** Hono matches handlers in
   registration order and a route answers without calling `next`, so a route
   registered above `app.use("*", limiter)` is never rate limited — and the test
   that catches it is one that asserts a 429, not one that asserts a 200.
8. Add the row to the README endpoint table, add a `CHANGELOG.md` entry, and
   re-run the three gates.
