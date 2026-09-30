# REPORT-guard-09-gate — declaring what `bin/prime` is worth

**Packet:** `guard-09-gate` · **Branch:** `worker/guard-09-gate` · **Base:** `97d83e9`
**Not pushed.** The manager merges and pushes after the gate is green.

## The one-paragraph version

`bin/prime` was never missing — it exists, it is what AGENTS.md tells a
developer to run, and CI runs it verbatim. What was missing was any statement of
what it is *worth*, which is the whole subject of this packet: guard was one of
seven services with no `gate.yml`, so a developer could run `bin/prime`, see
green, and learn nothing — replacing the gate with `exit 0` would have left this
repository green. This packet writes the declaration against core's published
format, sets both floors from real runs, and proves the declaration can fail
four different ways. It found two things worth more than the file: `mise run
prime` does not resolve in this repository at all, and `bin/prime` never
executes the live Redis tier.

## 1. The two commands, measured

The brief asks for the developer-facing command and the CI command, because
they are often not the same. **Here they are the same, and that was worth
verifying rather than assuming.**

| | Command | Source |
|---|---|---|
| Developer-facing | `bin/prime` | AGENTS.md §Gates; `bin/prime --help` |
| CI | `bin/prime` | `.github/workflows/ci.yml` `prime` job, step `run: bin/prime` |
| Fleet spelling | **`mise run prime` — does not resolve** | `mise.toml` has no `[tasks]` |

So AGENTS.md's rule "CI runs `bin/prime`, not a CI-only variant" is **true**,
verified by reading the workflow rather than trusting the job's name. That is
the good news, and it is the reason this repository was in better shape than the
packet assumed.

### Finding 1 — the fleet's spelling does not exist here

`mise.toml` carries `[tools]` (bun 1.3.12, node 22.12.0) and `[env]`, and **no
`[tasks]` table**. `mise tasks` in a clean worktree prints nothing at all.

Every one of the six existing adopters declares `gate.miseTask: prime`. guard
cannot: naming a task the repository does not have is `gate.task-missing`, a
**failure**. The honest declaration of a repository with no task is no task, and
omitting `miseTask` produces no finding at all — `check_mise_task` only reports
`gate.task-undeclared` when the config actually *has* tasks.

**Judgement call, recorded rather than fixed.** I did not add
`[tasks.prime] run = "./bin/prime"` to `mise.toml`. It would have made the
declaration prettier, but it changes how the repository is driven and would make
`gate.miseTask` true going forward while every historical claim in the file
stayed false. This packet is one repository's *declaration*; adding a task
runner is a different decision, and it belongs to whoever owns guard's developer
workflow. Flagged for the manager.

The cost of the omission is small and worth stating: `gate-check` will not be
able to cross-check guard's task against its entrypoint, because there is no
task. The entrypoint itself is still checked — it must exist and be executable.

## 2. What was measured, before anything was declared

Every number in `gate.yml` came from a run on this machine (bun 1.3.12, mise
2026.8.4, macOS arm64, on a saturated host — load average >100, so one suite at
a time throughout).

| Run | pass | skip | fail | total |
|---|---|---|---|---|
| `bin/prime`, cold (no `node_modules`) | **428** | **14** | 0 | 442 across 19 files |
| `bin/prime`, warm | 428 | 14 | 0 | 442 across 19 files |
| `bun test` with `GUARD_REDIS_URL` set | **442** | **0** | 0 | 442 across 19 files |
| `bun test src/middleware/rateLimitRedisLive.test.ts`, no Redis | 0 | **14** | 0 | 14 across 1 file |
| same file, real `redis-server` on 127.0.0.1:6399 | **14** | 0 | 0 | 14 across 1 file |

The fourth and fifth rows are how the 14 skips were **attributed** rather than
assumed: running the live tier alone with no Redis gives `0 pass / 14 skip`, so
the 14 are that file and nothing else.

Wall clock: ~36s for a cold `bin/prime` including the install; ~8–10s for the
suite alone. `timeoutSeconds: 900` is deliberately generous for a cold checkout
on a loaded machine.

### Finding 2 — `bin/prime` never runs the live Redis tier

**`bin/prime` does not set `GUARD_REDIS_URL`, so the live Redis tier is skipped
on every developer run and on CI's `prime` job.** The 14 tests that execute
`GCRA_LUA` against a real server have never run inside `bin/prime` — and the
whole reason `rateLimitRedisLive.test.ts` exists is that every other test
transcribes the Lua into JavaScript and runs the *transcript*, so the script
itself is covered by review and by nothing else.

This is not a defect in the gate. It is a **named limit**, and the brief asks
for it by name:

> **Environment variable: `GUARD_REDIS_URL`.** Unset ⇒ the 14-test live Redis
> tier skips. `GUARD_REDIS_REQUIRED=true` converts that skip into a
> module-load throw. Only the `redis` CI job sets both, so **CI is the only
> place the tier is ever forced.**

The three pre-existing mechanisms that already police this are unaffected and
still do the work they were built for: `GUARD_REDIS_REQUIRED`, the `redis` job's
summary parse (fails on `0 pass` or any skip), and `test/noSkips.test.ts`, which
fails on any `skip` outside a one-entry allowlist. I added nothing to them —
they are already correct, and adding a fourth would be motion.

## 3. What the declaration says

`gate.yml`, against `core/schemas/gate.schema.json`, checked by
`core/harness/gate_check.py`:

- `command: [bin/prime]`, `entrypoint: bin/prime`, `timeoutSeconds: 900`.
- `miseTask` **absent**, deliberately (Finding 1).
- `external.selfContained: false` with two requirements — **bun 1.3.12 on
  PATH** and **registry.npmjs.org, once, on a cold checkout only**. Both
  satisfied by a bare command, so both report `gate.requirement-unproven` and
  neither moves the exit code. That is the tri-state contract working, and it is
  the same pair of warnings muse documents as expected.
- **No credential requirement, measured rather than read off the workflow.** The
  suite was run to green with no environment variable of any kind set:
  `test/fakeIdentity.ts` and `test/jwksServer.ts` are in-process stand-ins and
  the tests mint their own keys. No proof in the declaration would print a
  token, a key or a JWT, and nothing in this repository logs one.
- `ci.workflow: .github/workflows/ci.yml`, `ci.invokes: [bin/prime]`.

### The proofs, and why two of them carry numbers

| id | matches | min | job it does |
|---|---|---|---|
| `pass` | `^\s*([0-9]+) pass$` | **423** | decrease-detector on executed assertions |
| `files` | `^Ran [0-9]+ tests across ([0-9]+) files\.` | **19** | deleted-test-file detector |
| `install` | `^== bun install --frozen-lockfile$` | — | the install step ran |
| `typecheck` | `^== bun run typecheck$` | — | catches a **silent** typecheck skip |
| `ok` | `^== prime ok \(bun ` | — | the gate reached its last line |

Each was checked against a real run's full output: every one matches **exactly
once**, so `minimum` is read from a number and not from a substring of a longer
line. (`gate_check` reads the **last** match, so a later smaller count is still
caught.)

**Why 423 and not 428.** The house margin, matching muse (890 for 895) and
courier (530 for 535): a floor at exactly today's number has to be raised by
hand before a single test can be added, and a ratchet nobody can move is a
ratchet that gets deleted. It is still a detector — six lost tests is
`gate.floor`, a failure.

**Why 423 and not 442.** `bin/prime` prints 428 without Redis and 442 with it.
A floor that only holds when an environment variable happens to be exported is
a declaration that is red on a clean machine, so the floor is set from the
**smaller** of the two. A Redis run clears it by 19.

**Why `files` is exact.** This is the finding that changed the file, and it is
the reason I did not stop at one floor. See §4, breakage 1.

## 4. Red proofs — the gate can fail

A gate that has never been observed red is not a gate. Four breakages, each run
through `gate_check.py --prove`, each **exit 1**, all reverted:

| # | Breakage | Finding | Notes |
|---|---|---|---|
| 1 | `rm test/noSkips.test.ts` | `gate.floor` on `files` — *"reported 18 and the declaration's floor is 19"* | **taught the file something** |
| 2 | delete `scripts.typecheck` from `package.json` | `gate.proof-missing` on `typecheck` | the **only** failure; suite still ran and still passed 428 |
| 3 | `bin/prime` → body is `exit 0` | `gate.proof-missing` on **all five** | the case the format exists for |
| 4 | raise `pass` floor 423 → 429 | `gate.floor` on `pass` — *"reported 428 and the declaration's floor is 429"* | proves the floor is live |

**Breakage 1 is the one worth reading twice.** `test/noSkips.test.ts` holds 5
tests, so deleting it took the suite from 428 to **423** — exactly equal to the
`pass` floor. That proof stayed **green** through a deleted test file. Only the
`files` floor caught it. So the margin that is correct on `pass` is pure loss
on `files`, and a single floor would have let a five-test deletion through
unnoticed. The two are not redundant; that is now a measurement in the file
rather than an opinion.

**Breakage 2 is the strongest argument in the declaration.** `bin/prime` probes
for a `typecheck` script and, finding none, prints one line to stderr and
continues to the suite. The suite still ran and still passed 428 — a **green
gate over a repository that had stopped type-checking**, with the only evidence
on a stream that a summary scrolls past. Without the `typecheck` proof this
breakage is invisible. That is now `gate.proof-missing`, a failure.

**Breakage 3 is the brief's scenario, answered.** "A checker replaced by a
function that unconditionally exits 0 would leave this repository green." It does
not: all five proofs went red at once, by five independent findings rather than
by the exit code, so it cannot be talked green by editing one away.

No assertion was weakened, no sleep added, no retry count raised, no threshold
lifted. Every breakage is a deletion, a substitution, or a number — the only
honest way to make a gate red without changing what the suite verifies.

## 5. The residue: what CI checks that `bin/prime` does not

The declaration makes `gate.command` and `ci.invokes` agree, and they do. But
`check_ci` reads one workflow's `run:` bodies and nothing else, and guard's CI
runs **three** things the local gate does not:

| CI job | what it checks | in `bin/prime`? |
|---|---|---|
| `ci` (kit reusable) | install + typecheck + test, from **kit's copy** of the conventions | same *steps*, different command |
| `redis` | the live tier, forced via `GUARD_REDIS_REQUIRED` | **no** — Finding 2 |
| `manifest` | `cafaye.yml` against core's frozen schema | **no** |
| `image` | hadolint, `docker build --target test`, and the image's test-file set vs `find` | **no** — and it is the check that catches a test file the image does not copy |

So the packet's stated problem — "a developer runs `bin/prime`, sees green,
learns nothing" — is **narrowed, not closed**. What it is now closed against is
the strongest version of the attack (a gate that exits 0 having run nothing).
What remains is a genuine and honest residue: three CI jobs verify things the
local gate does not, and two of those three (`image`, `redis`) exist *because*
their subject cannot be verified from the host at all.

I did not try to fold any of them into `gate.command`. `bin/prime` is what
developers run, and widening the declared command to include a Docker build and
a Redis service would be declaring a gate nobody runs locally — the same defect
in the opposite direction, and the one `docs/gate.md` argues against. Naming it
here is the deliverable.

## 6. What this format could not express

`minimum` is a **lower** bound. guard's real risk is the skip count going *up*
— 14 → 428 is what deleting the live tier's tests, or converting them to
`test.skip`, would look like — and a lower bound cannot catch an increase. So
**this declaration cannot notice a tier that skipped when it should have run**,
and it does not claim to. The comment in `gate.yml` says so and points at the
three mechanisms that do.

This is the same limit muse records for `MUSE_CORE_SCHEMAS`, for the same
reason, and I mention it rather than let a reader assume the gap is closed. If
the format ever grows a `maximum`, this is the declaration that would use it
first.

## 7. Verification

Run in the worktree at `97d83e9` + this packet, one suite at a time:

```
python3 ../core/harness/gate_check.py .          # static
  → OK: 0 failure(s), 2 warning(s)   [both gate.requirement-unproven]   exit 0

python3 ../core/harness/gate_check.py --prove .  # runs the gate
  → OK: 0 failure(s), 2 warning(s)                                       exit 0

bin/prime
  → 428 pass / 14 skip / 0 fail / Ran 442 tests across 19 files
```

The 2 warnings are the tri-state contract, not a defect: the checker refuses to
run `bun --version` to see whether a bare command is on PATH, because an answer
that depended on the machine would be red on a laptop and green on CI. This is
the pair muse documents as expected.

Worktree state at commit: `git status` clean apart from `gate.yml`,
`CHANGELOG.md` and this report. The throwaway `redis-server` used for §2 was
shut down.

## 8. Open for the manager

1. **`mise run prime` does not exist in guard.** The one place this repository
   does not match the other six adopters. Adding `[tasks.prime]` to
   `mise.toml` and then `miseTask: prime` to `gate.yml` would align it, in that
   order, in one commit. I left it alone deliberately — see §1.
2. **The live Redis tier is unreachable from `bin/prime` by construction.** Not
   proposed as a fix, but it is the sharpest thing in this report: 14 tests that
   exist specifically to execute `GCRA_LUA` are executed by exactly one CI job
   and by no developer. Whether `bin/prime` should *detect* a local
   `redis-server` and run the tier when one is present is a workflow decision,
   not a declaration decision.
3. **The skip ceiling is inexpressible in this format** (§6). Affects guard and
   muse identically.
