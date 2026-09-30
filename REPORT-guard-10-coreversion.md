# REPORT — guard-10: make the `^0.1.0` declaration true

**Branch:** `worker/guard-10-coreversion` · **Not pushed.**

The brief was two findings and four instructions. One of the two findings
reproduced exactly and cost one line. The other did not reproduce, and the
instruction built on it turned out to be the substantive half of this packet.

---

## Result

| Suite | Pass | Fail | **Skip** |
| --- | --- | --- | --- |
| `bin/prime` (no Redis — what CI's `prime` job runs) | **430** | 0 | **14** |
| `bin/prime` with `GUARD_REDIS_URL` set | **444** | 0 | **0** |
| `core` contract checker (`cafaye-contract --core ../core .`) | **0 violations** | — | 1 warning |
| `core` gate checker (`gate-check`) | **0 failures** | — | 2 warnings |
| `gate-check --prove` (runs the declared gate) | **green** | — | 2 warnings |
| `docker build --target test` | **430** | 0 | **14** |
| manifest vs **published** core schema | **valid** | — | — |
| hadolint (`--failure-threshold warning`) | **clean** | — | — |

**Pass and skip are separate counts above, as required.** The 14 skips are
`src/middleware/rateLimitRedisLive.test.ts` and nothing else — unchanged by this
packet, and I re-measured them rather than inheriting the number. The environment
variable that exercises them is `GUARD_REDIS_URL`; with it set and
`GUARD_REDIS_REQUIRED=true` the tier is **14 pass / 0 skip**, measured against a
real `redis-server` (v8.6.0, throwaway on 127.0.0.1:6399, since shut down).

The 430 vs 428 difference from `gate.yml`'s header is this packet's two new
tests. I did **not** touch `gate.yml`: the declared floors (423 pass, 19 files)
still hold, and that file is guard-09's declaration, not this packet's.

---

## 1. The version: reproduced exactly, and it really would have failed CI

Measured before changing anything:

```
guard/cafaye.yml:21   core: ^0.1.0
core/VERSION          0.2.0
core git tag          v0.2.0
```

`core/harness/bin/cafaye-contract --core ../core .` against guard, **before**:

```
FAIL core.constraint-unmet cafaye.yml: core: core publishes 0.2.0 and this
service declares `core: ^0.1.0`, which 0.2.0 is not in [0.1.0, 0.2.0). Either
the service is compiling against a core version it said it would not, or the
declaration is stale. … core did not move under it, it said so in advance and
was not listened to.
exit 1
```

**After `core: ^0.2.0`:**

```
OK . conforms to core ../core (58c10b82f38d, 9fac31e891f1)
1 warning(s) — openapi.not-declared — and no violation
exit 0
```

The constraint was the only violation. `cafaye.yml` still validates against
core's manifest schema **fetched from the published URL** (not a local copy), so
`^0.2.0` is legal under the same schema CI uses.

---

## 2. The event claim: did not reproduce. guard has no event surface at all

> *brief: "guard's cafaye.yml publishes no events under the names core's catalog
> lists — verify what guard actually publishes/consumes and whether the 0.2
> grammar and catalog accept it."*

I checked the source rather than the manifest, because a manifest can only state
what its author wrote down:

```
$ rg -n "eventType|event_type|\.emit\(|EventEmitter|outbox|publish\(|nats|kafka|amqp|sqs|/events" src/ test/
test/jwksServer.ts:61    publish(...keys: TestKey[]): void     # a JWKS test double
test/jwksServer.ts:108   publish(...next: TestKey[]) {        # rotating test keys
```

Those are the only hits and they are a **key set**, not a message bus. There is
no publisher, no subscriber, no outbox and no bus client anywhere in guard.

So the real shape is: guard publishes **no** events and consumes **no** events.
`consumes: []` is accurate rather than empty-by-omission, `exposes.events` is
correctly absent, and the 0.2 grammar and catalog accept an empty event surface —
which is what a gateway that terminates auth and answers requests should look
like. **No finding here, and nothing to fix.** The brief's phrasing pointed at a
contract violation; the measurement says guard has no contract on that axis at
all.

---

## 3. The `openapi.not-declared` warning: measured in full, and deliberately not "fixed"

The one remaining warning is the honest kind — the harness telling me what it did
**not** check:

> a document is checked in here that `exposes.api` does not name, so every
> `openapi.*` rule skipped it … it is the difference between being checked and not
> being checked. Found beside the manifest: `openapi/v1.yaml`.

That is true and it is a real gap: `openapi/v1.yaml` is **1408 lines** and **not
one core rule has ever read it**. So I measured what declaring it costs, on a
scratch copy, before touching the manifest:

```
$ (scratch copy) cafaye-contract --core ../core .     # with exposes.api added
17 violation(s): openapi.errors-are-problems, openapi.idempotency-key,
                 openapi.paths-are-versioned
```

| Rule | Count | What it is |
| --- | --- | --- |
| `openapi.paths-are-versioned` | 6 | `/healthz`, `/readyz`, `/auth/{register,login,logout,me}` are not under `/vN` |
| `openapi.errors-are-problems` | 8 | the `500`s still use the v0 `{error, message}` envelope |
| `openapi.idempotency-key` | 3 | `registerUser`, `createSession`, `deleteSession` take no `Idempotency-Key` |

**I did not declare `exposes.api`, and here is the reasoning rather than the
omission.** Declaring it is not a manifest edit; it is publishing guard's HTTP
surface as a contract, and each of the three families needs a different thing I
do not own:

1. **The paths are a breaking API change to a live gateway.** Moving
   `/healthz` to `/v1/healthz` renames the endpoint every orchestrator and probe
   in the fleet hardcodes. `guard`'s own `AGENTS.md` fixes the probe split, and
   `openapi/v1.yaml` is held to the router **in both directions** by
   `test/openapiDocument.test.ts` — so editing the document without changing
   router turns guard's own gate red, and changing the router is a spec decision
   the manifest already reserves for the manager ("specs are manager-owned").
2. **The `500` envelope is an open decision this repository recorded itself.** It
   is "open decision 5" in the document's own header, and it needs a change in
   `src/`, which the brief scopes out ("keep to `cafaye.yml`, the files the
   checker names, `CHANGELOG`, your report").
3. **Idempotency-Key is a feature, not a declaration.** Adding the header to the
   document without the server honouring it would make `openapi/v1.yaml` a lie,
   which is the one thing a contract must not be.

The checker is **green** — exit 0 — and the warning's own text says it "does not
change the exit code". Turning a green-with-an-honest-warning into a red 17 is
not an improvement, and the alternative (declaring it and leaving 17 red) is
worse. **The 17 are measured, recorded here, and left for the packet that owns
guard's HTTP contract.**

### 3.1 One of the 17 is a core bug, reported rather than worked around

The brief said: *"If the checker names something that is a core bug, report it —
do not work around it."* It does.

`openapi.paths-are-versioned` has **no carve-out for probe endpoints**, and
`docs/openapi-conventions.md` says nothing about probes (I grepped it: no
`healthz`, no `readyz`, no "probe"). The rule is
`if not VERSION_PREFIX.match(path)` with `VERSION_PREFIX = ^/v(\d+)(/|$)`.

I did not take core-17's word for it — I ran the checker myself against the two
services that declare `exposes.api` and ship probes:

```
darkroom   FAIL openapi.paths-are-versioned  /healthz, /readyz     (9 violations total)
pantry     FAIL openapi.paths-are-versioned  /healthz, /readyz     (2 violations total)
```

**`pantry`'s *only* two violations in the entire fleet are these two paths.**
A fully-conforming service fails core's rule for having health and readiness
probes — the two endpoints every cafaye service has, and the two guard's
`AGENTS.md` describes as deliberate and load-bearing.

**This is a core-side gap, and it is not guard's to fix.** Renaming guard's
probes under `/v1` to satisfy it would be the workaround the brief forbids: it
would break a working fleet convention to satisfy a rule that has not considered
the convention. The fix belongs in core — an exemption for the two probe paths,
and a line in `openapi-conventions.md` saying which paths are exempt and why.
Until then, **no service in this fleet with probes can declare `exposes.api`
cleanly**, which is the second reason the warning is the right state to be in
for guard today.

---

## 4. The toolchain lesson: reproduced, then fixed, then red-proved

The brief: *"if guard's gate fails on a wrong-toolchain ruby/node/bun picking up
the system binary, make the gate FAIL LOUDLY naming the pin, not red-herring on
module errors."*

**It reproduced exactly.** `bin/prime`'s only toolchain precondition was
`command -v bun`. I put a bun 1.2.9 first on `PATH`:

```
== bun install --frozen-lockfile
fake bun 1.2.9: cannot find module 'hono'          <-- the red herring
```

That is the whole defect. It names a **package**, so it sends the reader to
`package.json` and `bun.lock` — the two files that are not wrong — and says
nothing about the runtime that is. cafaye-rb's gate failed this way on a Ruby
that *was* on `PATH` and was not the one mise had installed.

**The fix, in `bin/prime`:**

- `require_pinned_bun` compares `bun --version` to the pin **before the install**,
  so nothing is spent before the refusal. It exits **127** — the code the script
  already used for an absent toolchain, because a wrong runtime is not a
  different kind of problem from a missing one.
- **The pin is read, never written.** It comes from `package.json`'s
  `packageManager`, the field bun itself honours as an exact version.
  `pins.test.ts` already holds that field, `mise.toml`, the `Dockerfile` and
  compose to one number — a sixth copy inside the script would be the only one
  nothing checks.
- **An unreadable pin is also a loud 127**, not a skipped check. A gate that
  cannot find its own precondition cannot be debugged from its own output.
- The closing banner prints the version the check **admitted** rather than
  re-reading `--version` at the end, so the banner cannot disagree with the
  check that let the run start.

**Red proof, both directions** (`pins.test.ts`, against a stand-in bun first on
`PATH` — behaviour, not text):

| Stand-in bun | Exit | What it prints |
| --- | --- | --- |
| `1.2.9` | **127** | `wrong Bun on PATH — this repository pins 1.3.12 and found 1.2.9`, plus the resolved path and both remedies |
| `1.3.12` | **0** | reaches `prime ok (bun 1.3.12)` |

The assertions include the negative that matters: the wrong-version run must
**not** print `cannot find module`, and must **not** have printed an install
banner. And the pinned version is asserted to be *admitted* — a check that only
ever refuses is indistinguishable from a script that is simply broken.

### 4.1 The COPY chain followed, in the same commit

The suite now **executes** `bin/prime`, so the image needs it. Three files moved
with it, because a check that runs on the host and not in the image is a check
whose absence nobody notices — the exact defect `pins.test.ts` was written for:

- `Dockerfile` — `COPY bin ./bin` in the test stage
- `.dockerignore` — `!bin`. A **directory** needs the negation as much as a file
  does, or the context drops everything under it and `COPY bin ./bin` names a
  path that is not there.
- `test/dockerStage.test.ts` — `bin/prime` added to `SUITE_INPUTS`, so the
  tripwire that caught this same class of bug catches it here too.

**Verified in the built image, not just on the host:** `docker build --target
test` reports `430 pass / 14 skip / 0 fail`, both new tests appear in the image's
own output, and CI's image-vs-repository diff still reports **19 test files in
agreement**.

---

## 5. What I did not do, and why

- **Did not declare `exposes.api`.** §3 — it is a contract publication and a
  breaking API change, and it would trade a green honest warning for 17 red.
- **Did not touch `gate.yml`.** Its floors still hold and it is guard-09's
  declaration.
- **Did not edit core or any other service.** The core gap in §3.1 is reported,
  not patched.
- **Did not push.**
- **No sleeps, no raised retries, no loosened assertions.** Nothing was deleted
  or thresholded to make anything green; the only floors in play (`gate.yml`'s
  423/19) were left exactly as they were, and the suite grew by two tests.
- **No secret was read, logged or printed.** The suite is hermetic — in-process
  JWKS and identity doubles, keys minted with `crypto.getRandomValues`. Nothing
  in this packet logs a token, a key or a JWT, and the new failure message
  prints a **version number and a filesystem path** only.

## 6. Files changed

| File | Change |
| --- | --- |
| `cafaye.yml` | `core: ^0.1.0` → `^0.2.0` (one line) |
| `bin/prime` | the pin is now checked, loudly, before any work |
| `pins.test.ts` | two tests: the red proof of the pin check, both directions |
| `Dockerfile` | `COPY bin ./bin` — the suite now runs `bin/prime` |
| `.dockerignore` | `!bin` — a directory needs the negation too |
| `test/dockerStage.test.ts` | `bin/prime` in `SUITE_INPUTS`, so the tripwire covers it |
| `CHANGELOG.md` | `Changed` and `Fixed` at the top of `[Unreleased]` |
| `REPORT-guard-10-coreversion.md` | this file |

## 7. For the manager

1. **The bump is the whole of the version finding, and it is green.** guard now
   declares what it compiles against. Nothing else in this packet was needed to
   satisfy `core.constraint-unmet`.
2. **The `openapi.not-declared` warning is a decision for you, not a task.** §3
   has the measured 17. My recommendation is that guard's next packet own the
   HTTP contract (it is the only thing that can move `/healthz` and the `500`
   envelope), and that it do so *with* `exposes.api` declared, not before.
3. **One core bug, for core's queue:** `openapi.paths-are-versioned` has no
   probe exemption, so `pantry` — whose only two violations are `/healthz` and
   `/readyz` — cannot be clean. Needs an exemption plus a line in
   `openapi-conventions.md`. §3.1.
4. **The toolchain lesson is now a gate, not a habit,** in this repository and
   enforced in the image. If `kit`'s `bin/prime` templates are to carry it
   fleet-wide, this is the shape: read the pin from `packageManager`, compare,
   exit 127 naming both numbers, and test it against a stand-in runtime in both
   directions.
