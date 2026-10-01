# Changelog

All notable changes to `guard` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). `core`'s
mini-semver grammar (`^`, `~`, `>=`, exact) is what `cafaye.yml` uses; npm
dependency versions follow npm's own rules.

## [Unreleased]

### Added

- **`LICENSE`: guard is MIT.** The repository shipped no licence file at all,
  which is not "unlicensed, therefore free" — it is **all rights reserved**,
  the default copyright position when a public repository grants nothing, so a
  stranger could not legally run, modify or resell any of it. `package.json`
  already declared `"license": "MIT"` and is now backed by the grant itself.

  MIT is the fleet decision and the reason is the service-registry model: guard
  is the public edge every request enters through, so a consumer's first contact
  with the fleet's licensing is guard's. MIT keeps adding guard a decision about
  dependencies rather than about obligations; copyleft would attach one to every
  downstream consumer.

  The copyright line matches the three repositories that already shipped a
  licence (`cafaye-py`, `cafaye-rb`, `cafaye-ts`) exactly: `Copyright (c) 2026
  cafaye`. All fifteen now hold byte-identical licence text.

### Fixed

- **Two cross-tenant holes in the API-key store: a key id was a tenant.** D18
  measured guard at zero negative tests, and the two that existed when this
  packet started were both in `memoryApiKeyStore` — the seam `TODO(guard-07)`
  moves to Redis, and the trait the future `/v1/api-keys` route will call.

  1. **`revoke(id)` took no account at all.** A key id is not a tenant: ids are
     displayed to a holder to tell two keys apart and handed to an operator for
     revocation, so any caller who learned one could name it. Any caller could
     therefore withdraw *any* account's credential — a cross-tenant **write**,
     and a denial of service wearing a support action's clothes. It now takes the
     account and refuses to touch a record that is not that account's:
     `revoke(accountId, id)`.
  2. **`list(accountId)` resolved ids through a map keyed by id alone.** Two
     accounts holding the same id made one account's listing return the *other*
     account's record — hash, prefix and scopes included, which is credential
     material — under its own query. Silent, because the record returned is real
     and well-formed. `byId` being keyed by id made a collision the only thing
     standing between a caller and another tenant's keys, and a UUID is not a
     guarantee, it is a probability. It now filters on the record's own
     `accountId` rather than trusting membership of an id set.

  Neither was reachable from a route today — guard has no endpoint that issues or
  revokes a key, which the README says under "Not built yet". Both are load-bearing
  anyway, because the signature is what the next author and the next store
  implementation read. Both now refuse by **absence**: `revoke` on a foreign key
  is a no-op with no error and no return value, and leaves `revokedAt` at 0, so
  an attempt that missed its scoping leaves nothing an operator could mistake for
  a real withdrawal.

  **11 account-scoped entry points** enumerated and negatively tested, derived
  from the code rather than declared: `test/tenantEntryPoints.test.ts` reads the
  routes off Hono's own array, the account-scoped store methods off the interface
  declarations, and every `status: 403` in production source, and requires each
  to have a negative case named in `src/middleware/tenantIsolation.test.ts`. All
  four operation kinds are covered (read 5, list 1, update 3, delete 2) — delete
  because a service that scopes reads and forgets deletes is the common shape.

  **No `403` was found for a resource the caller cannot see, and none was
  added.** The only two `403`s guard writes are a capability failure
  (`requireScope`: the token authenticated and lacks a scope) and an origin
  failure (`requireSameOrigin`) — both facts about the *caller*, which they
  already know, and neither naming a resource, so neither can confirm one exists.
  The distinction is asserted in both directions: a tenancy `403` would be a
  finding to fix, and a `404` for a capability would throw away a distinction the
  caller is entitled to.

  Two guard-authored defects, both found by *running* the guards and written up
  in `REPORT-guard-11-isolation.md`: a listing fixture built through
  `createApiKeyAuth.issue` was a silent no-op (it is idempotent on the hash, so
  the id collision the case needed never happened, and the test passed with the
  filter deleted), and a Redis-key assertion that recomputed `bucket()`'s digest
  in the test passed with the digest deleted from `rateLimit.ts` — a copy of the
  production logic is not a check on it. Both now observe the real thing: the
  store, and the key `eval` was actually handed.

  Five divergences were planted and reverted, each caught by the named test; the
  transcript is in the report.

### Changed

- **`ApiKeyStore.revoke` takes an account.** `(id: string)` → `(accountId: string, id: string)`.
  A trait change rather than an internal edit, and the seven call sites in the
  suite were updated with it. A store implementation written from the old
  signature is a cross-tenant write waiting for a route.

- **`core: ^0.1.0` → `^0.2.0`. The declaration was the stale half, not the code.**
  guard's content was already 0.2-shaped; the constraint was a number nobody
  re-read. `core` publishes `VERSION` = `0.2.0` (tag `v0.2.0`), and its
  `core.constraint-unmet` rule resolves a service's declared `core:` against it —
  so guard failed CI **on its own declaration**, and the failure named the right
  file. Measured before and after, against core's contract checker:

  ```
  before   ^0.1.0  exit=1  FAIL core.constraint-unmet
  after    ^0.2.0  exit=0  OK, 1 warning
  ```

  This is the check `0.2.0`'s own changelog promised and could not perform. The
  brief's second claim — that guard publishes no events under core's catalog
  names — **did not reproduce and is not a defect**: guard has no event surface
  at all. `consumes: []` is accurate, there is no `exposes.events`, and no bus,
  outbox or publisher anywhere in `src/`. The 0.2 grammar and catalog accept an
  empty event surface, which is what a gateway that answers requests and
  subscribes to nothing should look like. Verified by reading the source, not by
  inferring it from the manifest.

### Fixed

- **`bin/prime` accepts a bun that is present and wrong.** The gate's only
  toolchain precondition was `command -v bun`, so a bun from a system install, a
  global upgrade or a stale CI image — anything ahead of mise's shims on `PATH` —
  ran the entire gate silently. The failure it produced was a red herring:
  `cannot find module 'hono'`, which names a *package*, points the reader at
  `package.json` and `bun.lock`, and says nothing about the runtime that caused
  it. This is the cafaye-rb lesson, reproduced here on bun: that gate failed on a
  Ruby that was on `PATH` and was not the one mise installed.
  - The gate now **names the pin and the version it found**, and exits **127** —
    the code it already used for an absent toolchain, because a wrong runtime is
    not a different kind of problem from a missing one. The check runs *before*
    the install, so nothing is spent before the refusal.
  - **The pin is read, not written.** `bin/prime` takes it from `package.json`'s
    `packageManager`, the field bun itself honours as an exact version, so there
    is no copy of the number in the script to drift. `pins.test.ts` already holds
    that field, `mise.toml`, the Dockerfile and compose to one number; a sixth
    copy here would be the only one nothing checks.
  - A pin that **cannot be read** is also a loud 127, not a skipped check. A gate
    that cannot find its own precondition cannot be debugged from its own output.
  - **Both directions are tested**, in `pins.test.ts`, against a stand-in bun
    first on `PATH` rather than asserted as text: a wrong version must exit 127
    naming both numbers, must **not** print `cannot find module`, and must not
    have printed an install banner; the pinned version must be admitted and reach
    `prime ok (bun 1.3.12)`. A check that only ever refuses is indistinguishable
    from a script that is simply broken.
  - The closing banner reports the version the check **admitted**, not a second
    reading of `--version` at the end of the run — a banner that re-reads the
    runtime can disagree with the check that let the run start.
  - **`Dockerfile` / `.dockerignore` / `test/dockerStage.test.ts` follow, in the
    same commit.** The suite now *executes* `bin/prime`, so the image needs it:
    `COPY bin ./bin`, `!bin` in `.dockerignore` (a directory needs the negation
    too, or the context drops everything under it), and `bin/prime` added to
    `SUITE_INPUTS`. Verified in the built image — both new tests run there, and
    the CI image-vs-repository diff still reports 19 test files in agreement. A
    check that runs on the host and not in the image is a check whose absence
    nobody notices, which is the exact defect `pins.test.ts` was written for.

### Added

- **`gate.yml` — the gate is now declared rather than discovered.** `bin/prime`
  exists and CI runs it, so the gate was never *missing*; what was missing was
  any statement of what it is worth. A developer here could run `bin/prime`,
  see a green result, and learn nothing about whether the suite could detect
  anything — replacing `bin/prime` with a script whose whole body is `exit 0`
  would have left this repository green. The declaration states the command
  (`bin/prime`), the entrypoint, two numeric floors, and five lines the gate's
  own output must contain. Written against `cafaye/core`'s
  `schemas/gate.schema.json` and checked by `harness/gate_check.py`, which now
  reports **0 failures, 2 warnings** here — both the expected
  `gate.requirement-unproven` for a bare command on PATH, which is the
  tri-state working and never moves the exit code.
  - **Two floors, not one, and the reason was measured.** `pass` is floored at
    **423** against a measured 428 — the house margin muse and courier use, so
    adding a test does not force a same-commit bump. `Ran … across N files` is
    floored at **19** exactly, with no margin, because deleting
    `test/noSkips.test.ts` took the suite from 428 to 423: the `pass` floor
    stayed **green** through a deleted test file and only the file-count floor
    caught it. The two are not redundant, which is not something a single floor
    could have told us.
  - **The declaration is red-proved four ways**, every one exiting 1: the
    deleted test file (`gate.floor` on `files`); a deleted `typecheck` script
    (`gate.proof-missing` on `typecheck`, and it was the *only* failure);
    `bin/prime` replaced by `exit 0` (all five proofs red at once); and the
    `pass` floor raised one above the measurement (`gate.floor` on `pass`).
    No assertion was weakened, no sleep added, no retry count raised.
  - **A silent typecheck skip is now a failure.** `bin/prime` probes for a
    `typecheck` script and, finding none, prints a line to stderr and
    continues to the suite — a green gate over a repository that had stopped
    type-checking, with the only evidence on a stream a summary scrolls past.
    The `typecheck` proof turns that into `gate.proof-missing`.

### Known

- **`mise run prime` does not resolve in this repository, and `gate.yml` does
  not pretend otherwise.** `mise.toml` carries `[tools]` and `[env]` and no
  `[tasks]` table, and `mise tasks` prints nothing. Six of the thirteen services
  declare `gate.miseTask: prime`; guard's declaration names no task at all,
  because naming a task this repository does not have is `gate.task-missing` —
  a failure over a repository that is fine. `gate.command` names `bin/prime`,
  which is what AGENTS.md already tells a developer to run and what the `prime`
  CI job runs verbatim. Recorded rather than fixed: adding a `[tasks.prime]` is
  a change to how the repository is driven, not a declaration of what it
  already is.

### Fixed

- **A burst of forged tokens naming an unknown `kid` bought one JWKS fetch each,
  aimed at identity.** The refresh budget was a flag on the cached key set, set
  when the fetch *completed*. Every request already in flight when a refresh
  began therefore read the flag as unset and started a refresh of its own, so
  twenty-five simultaneous requests produced twenty-five fetches where the rule
  says one. Pre-auth, anonymous, and free to send: it needed no valid token,
  only a token-shaped string naming a key identity does not publish. The budget
  is now a cache-window number claimed **before** the await, so the burst gets
  one fetch and the rest are refused off the cached set with no network call. A
  refresh that *fails* spends the budget too — otherwise an unreachable identity
  is an unlimited fetch allowance for anyone naming a `kid`.
- **`X-Forwarded-For` accepted strings that are not addresses as bucket
  identities.** The filter was `[0-9a-f:.%]+`, which answers "is every character
  safe to write into a Redis key" rather than "is this an address". `deadbeef`,
  `cafe`, `...` and `999.1.1.1` all passed and each became a bucket of its own,
  so a caller able to put an entry in the trusted position minted a fresh
  allowance per request by varying a string that was never an address — the
  limiter was decorative in exactly the deployment that configures it. `clientIp`
  now parses with `isIP` from `node:net` (a runtime builtin, no new dependency),
  which also settles the `%zone` suffix the old charset had to tolerate. Real
  addresses in every shape a proxy emits are still read, and `::1` is still an
  address: a filter that refuses everything is the same defect pointing the other
  way.
- **An identity 5xx was dropped with no log line at all.** `call()` logs when
  the *transport* fails; an identity that is up and returning 500 — a broken
  deploy, an OOM, a panic — reached `unusable()` silently. Every login in a
  deployment failed with one status and nothing was recorded for an operator to
  correlate, which is a silent outage whose only signal is the browsers of its
  users. `unusable()` now records the target URL and the status. **Never the
  body**: a dependency's error page is exactly where a credential turns up, so
  the line records the shape of the answer and not its contents.

### Added

- **`src/edge.test.ts` — the public edge under attack.** Fifteen negative claims
  with the mechanism that makes each one true: no client-controlled outbound
  fetch (a body carrying `169.254.169.254` reaches identity as data, never as a
  target; no request header moves the target; a redirect from identity is not
  followed), path handling (thirteen spellings of `/v1/me` all meet the auth
  gate; a traversal out of `/v1` mints no session), header and log safety (CRLF
  in a path, CRLF in `X-Forwarded-For`, a policy name carrying a second
  structured-field item, an upstream error body), and the probe exemptions being
  exact paths rather than prefixes. No network: identity is an injected `fetch`
  and every key is generated in-process.
- **`test/noSkips.test.ts` — the suite cannot skip itself.** `bun test` exits 0
  on a run where every test was skipped, which is how an environment-gated tier
  gets added and then quietly never runs again. The Redis tier already carries
  two mechanisms against that (`GUARD_REDIS_REQUIRED=true` and the `redis` job's
  `0 pass` check) and both protect **one file**. This reads the suite's own source
  and fails on any `skip`, `skipIf`, `todo` or `only` outside a one-entry
  allowlist, naming the file in the failure, and separately asserts that the
  Redis tier still carries the `GUARD_REDIS_REQUIRED` guard. Its detector is
  assembled from arrays at runtime rather than written as a regex literal,
  because a literal matching `\.\s*(skip|skipIf)` matches its own source.

- **The README's stated reason the live Redis tier cannot run in the image was
  wrong, and a reader would have been misled by it.** It claimed "buildkit refuses
  `--network=host`". On Docker 29.4.0 the flag is **accepted** — and a `RUN` under
  it still cannot reach a server on the host's network, so the conclusion held
  while the mechanism did not. That is the worse combination: someone trying to
  close the gap would find the flag accepted, see a build that looked fine, and
  conclude the tier was easy to enable. Now states what was measured — the flag is
  accepted and buys nothing, and the real obstacles are the absent sidecar
  mechanism and the 30 MB of stage to install a server the `redis` job already
  runs.
- **`docker build --target test` now runs the same tests a host run does.** It ran
  **392 tests across 15 files** where a host run ran **399 across 16**. The seven
  missing were `pins.test.ts`, which sits at the repository root and which the test
  stage's `COPY` list — `src`, `test`, `openapi` — never named. So the image never
  executed the test that asserts the Bun pin in `package.json`, `mise.toml`, the
  Dockerfile and compose all agree: the check that would have noticed the image
  disagreeing with the repository was the one test the image did not run, and the
  build was green throughout. A test file the image does not have does not fail, it
  is not executed, so nothing in the build output said so.
  - **`test/dockerStage.test.ts` holds the `COPY` list to the repository.** It
    walks the tree for `*.test.ts` and fails when the test stage's copy chain does
    not name one, so adding a test file now fails `bin/prime` until the list names
    it. It runs wherever the suite runs — the laptop, kit's workflow, the image —
    because a check kept outside the suite is a check somebody has to remember.
  - **The `image` CI job diffs the image's test files against `find`.** The test
    above reads the Dockerfile and is therefore blind to `.dockerignore`: a
    `COPY src ./src` with an excluded subdirectory copies the rest and the build
    stays green, which was verified against buildkit rather than assumed. The suite
    emits every test file it discovered and CI compares the sets, so the check that
    reads the *built image* covers the half the Dockerfile reader cannot see.
  - **The comparison is over test files, not test counts**, on purpose: the live
    Redis tier skips in-image by design, so the pass count legitimately differs from
    a host run with Redis, and the file count cannot.
  - **The list stayed explicit rather than becoming `COPY . .`.** A whole-context
    copy is always a superset, which makes the tripwire vacuous — it would pass
    without saying anything — and it puts the doubles in `test/` one careless edit
    from the runtime stage. A new assertion holds the runtime stage to copying no
    test tree and no whole context.
  - `.dockerignore` also excluded `.gitignore`, `docker-compose.yml` and
    `Dockerfile`, so the `COPY` list could not name the three files `pins.test.ts`
    reads. The symptom was a hard `"/x": not found` at build time rather than a
    silent skip, but a list naming a path the build context does not contain is
    still a wrong list, and both files now carry the fix.
  - Both breaks were introduced on purpose and observed going red: a root-level
    test file the list omits, and a directory `.dockerignore` drops. In both cases
    `docker build --target test` stayed **green** at 417 across 17 and the new
    check reported the missing file.
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

- **`openapi/v1.yaml`, and a test that holds it to the router in both
  directions.** guard was the only service in the fleet with no OpenAPI document,
  so it was the one surface a generated client could not describe. The document is
  3.1.0 at `info.version: 1.0.0` — a new document, so there is no compatibility
  promise to keep — and it covers all seven routes `createApp` registers: the two
  probes, `GET /v1/me`, and the four `/auth` browser operations.
  - **The refusals are documented, not just the successes.** Every non-2xx
    response is `application/problem+json` and the shape is declared **once**, as
    `components.schemas.Problem`, with every error response referencing it — a
    document that only describes the happy path is the usual way an OpenAPI file
    becomes a lie, and refusing requests is most of what this service does. The
    `429` carries the whole rate-limit family: `RateLimit-Policy`, `RateLimit`,
    the un-prefixed trio, the `X-RateLimit-*` trio and `Retry-After`. The family is
    on the success responses too, because a client that renders a quota meter
    reads it from a `200`.
  - **The header says what the document leaves out, and how.** `ALL /v1/*` and
    `ALL /*` are `app.use(…)` mounts, not routes: Hono records every mount with the
    method `ALL`, so they are excluded as **exact method+path pairs** and never as
    a `/v1/` prefix. A route added under `/v1/` next year is a `GET` and is not
    covered by that carve-out; `GET /v1/me` is under that prefix and is in the
    document, which is the standing proof. A test asserts exactly that, and the
    header and the test name the same normalised keys, so the two cannot drift.
  - **Both directions were proved red.** A planted `GET /v1/api-keys` fails
    `documentedNotServed` with the file and line to fix; deleting `GET /v1/me`
    fails `unexplained`. Both were reverted.
  - **Seven departures from `core/docs/openapi-conventions.md` are recorded in the
    document's header as open decisions**, not resolved locally: `exposes` is
    still absent from `cafaye.yml` even though the document now exists; the
    browser surface and the probes are not under `/v1`; an API key is not a bearer
    JWT; the browser surface has a same-origin gate and no CSRF token; `404` and
    `500` are still the v0 `{error, message}` shape and guard therefore produces
    no `not_found` or `internal` problem code; `/readyz`'s `503` is
    `application/json` (the conflict `identity` also records, so the ruling wants
    to be fleet-wide); and `Idempotency-Key` is not honoured on
    `POST /auth/register`. The two already open in `cafaye.yml` — RS256 only, the
    `scope` claim, the default issuer, and the three extra error codes — are
    referenced rather than restated.
- **`RATE_LIMIT_HEADERS` is exported from `middleware/rateLimit.ts`**, and
  `rateLimit.test.ts` asserts the list and what `announce` actually sets are the
  same set. The document has to name all eight fields, and a list written out in a
  YAML file is a list that can only fail for a name somebody remembered. A header
  added to the middleware and not to the document now fails the gate instead of
  reaching a client undocumented.
- **`PROBE_PATHS` is exported from `index.ts`.** The document declares a `429` on
  every operation *except* the two the limiter spares, and that exemption is a
  claim about this set rather than about two paths somebody typed into a test.
- **The Dockerfile's test stage copies `openapi/`.** Without it the tripwire would
  not run in the image that ships, and the suite would be green having checked the
  document in no tree at all.

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
