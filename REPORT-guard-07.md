# guard-07 — the Docker test image ran seven fewer tests than the laptop

> **DECISION NEEDED (D1): kit owns all seven Dockerfiles, and none of them has a
> test stage at all.** Every template is `build` → `runtime`; `docker build
> --target test` does not exist to be wrong about. So the bug this packet fixed in
> guard is the *smaller* version of a fleet-wide gap: the other six services have
> no in-image suite whatsoever, and the brief's own framing — "a CI run that
> verifies less than it appears to is worse than no CI" — applies to all of them
> with nothing to fix, rather than to guard with seven tests to recover. A test
> stage per template is a kit packet, not a guard one. The two files written here
> (`test/dockerStage.ts`, `test/dockerStage.test.ts`) are the reusable half: they
> parse stages, `COPY` chains and `.`, and know nothing about Bun. They drop into
> another service's `test/` unchanged — but a porter has to *decide* two things
> rather than inherit them, which is why this is raised rather than done.
>
> **DECISION NEEDED (D2): all seven kit templates end their runtime stage in
> `COPY . .`,** including the identity doubles' siblings — and that is precisely
> the pattern this packet argues against. `COPY . .` makes the tripwire vacuous
> (a whole-context copy is always a superset, so the check passes without saying
> anything) *and* puts an entire test tree one careless edit from the runtime
> image. The two are in tension: fixing the leak means copying an explicit list,
> which is exactly the maintenance burden that produced the original bug. A porter
> adopting this check has to break that `COPY . .`, and should decide
> deliberately whether an explicit runtime list or a generated one suits the
> service. Rust and Go are already clean here (they copy one binary out of
> `build`); the other five are not.
>
> **DECISION NEEDED (D3): the live Redis tier cannot run inside the image, and I
> believe it should not** — but that is a judgement about a check that exists
> nowhere else, so it belongs to the manager rather than to me. Details and the
> measurement below. Recorded here as a documented limitation, which the brief
> allows, rather than a gap I closed or one I left silent.

## The finding, and what it was

`docker build --target test` reported **392 tests across 15 files** where a host
run reported **399 across 16**. The missing file was **`pins.test.ts`**.

Confirmed against guard-06's own Dockerfile rather than taken on trust: the test
stage was `COPY tsconfig.json`, `COPY src`, `COPY test`, `COPY openapi`. A file
at the repository root is in none of those. `pins.test.ts` holds exactly **7**
tests, which is the 399 − 392, and it reads `package.json`, `mise.toml`,
`Dockerfile`, `docker-compose.yml`, `bun.lock` and `.gitignore`.

The damage is not the seven tests. It is *which* seven: `pins.test.ts` is the
test that asserts the image and the repository agree on the Bun pin. Inside the
image it did not run. The one check that would have noticed the image drifting
from the repository was the check the image did not execute — and a test file
that is not copied does not fail, it is simply absent, so the build stayed green
and its log was identical to a correct one.

## How the file set is derived now, and why not the alternatives

The test stage still names an explicit list. What changed is that **the list is
checked rather than trusted**, by two mechanisms covering two disjoint holes.

**Rejected: `COPY . .`.** Always a superset, so every assertion below passes
without saying anything — the check becomes a tautology that reports success for
any Dockerfile including a broken one. It also drags the identity and JWKS
doubles in `test/` one careless edit away from the runtime stage. A test asserting
`copied).not.toContain(".")` holds this line in place.

**Rejected: a derived list** (`COPY package.json bun.lock* ./` then a glob, then
a `find`-driven copy). A glob cannot enumerate a fixed set of test files, and the
find-driven version is a build step whose output is a claim nobody reads. Both
move the inventory out of the Dockerfile and into a mechanism, which is the same
invisible-list problem wearing a different hat.

**Chosen: assert the two agree.** The explicit list stays, for build efficiency
and so the doubles stay out of the runtime stage, and two checks hold it to
reality. Which one catches what is the substance of this packet, because the two
holes are genuinely disjoint:

| Hole | Caught by | Why the other misses it |
| --- | --- | --- |
| A test file the `COPY` list never names | `test/dockerStage.test.ts` (in-suite, local) | the CI diff sees it too, but only after a full build |
| A path the list names that `.dockerignore` then partly drops | `image` CI job (reads the built image) | **the Dockerfile reader cannot see `.dockerignore` at all** |

The second row is the one that justifies two mechanisms rather than one. A
`COPY src ./src` with an excluded subdirectory copies the rest of the directory
and the build stays green — I verified this against buildkit rather than assuming
it. The Dockerfile reader has no access to the context rules, so it would pass.

## The check that fails when the image and the repository disagree

`test/dockerStage.test.ts`, in the suite so it runs wherever the suite runs
(`bin/prime`, kit's workflow, and the image itself):

```
error: 1 test file(s) are in the repository and not in what the test stage copies:
  scratch-break.test.ts
```

and the CI step, which reads the *built image* rather than the Dockerfile:

```
CI STEP: RED — the image's test files and the repository's disagree:
2d1
< scratch-break.test.ts
```

The reader (`test/dockerStage.ts`) raises rather than under-reads, because a
reader returning nothing agrees with another reader returning nothing: no stage by
that name, a line continuation, a cyclic stage chain and the JSON-array `COPY`
form are all errors. The CI step also fails when the image reports *no* test files
at all, since an empty report would otherwise make the diff pass by declaring
every file removed.

## The deliberate breaks, and the red they produced

Both introduced, both observed, both reverted. Neither is a test I wrote to pass.

**Break A — a root-level test file the list omits.** Added `scratch-break.test.ts`
at the repository root, the exact shape `pins.test.ts` had.

- `docker build --target test` → **green, exit 0**, `417 tests across 17 files`,
  byte-identical to the unbroken build. The missing file is invisible.
- `bun test test/dockerStage.test.ts` → **red**, names the file.
- CI diff → **red**, `2d1 < scratch-break.test.ts`.

**Break B — a directory `.dockerignore` drops.** Added `src/buried/buried.test.ts`
and `src/buried` to `.dockerignore`.

- `docker build --target test` → **green, exit 0**, `417 across 17` again.
- `bun test test/dockerStage.test.ts` → **green, 18 pass**. It reads the
  Dockerfile, sees `COPY src`, and believes the file is covered. It cannot see
  `.dockerignore`, and saying so is the point.
- CI diff → **red**, `4d3 < src/buried/buried.test.ts`.

**Break B is why there are two checks.** In A the local check is the fast one and
the CI diff is the backstop; in B the local check is *blind* and only the CI diff
sees it. Neither alone closes both. One line each: A proves the tripwire fires;
B proves it fires where the first one cannot reach.

## The Redis tier in-image

The honest answer is **no, and it should not** — recorded as D3.

I did not take the previous note's reasoning on faith; I measured it. The README
claimed "buildkit refuses `--network=host`". On Docker 29.4.0 **the flag is
accepted** — the build succeeds — and a `RUN` under it **still cannot reach a
server on the host's network**: a connect probe fails both with and without the
flag (refused at 0.47s with it, 2.47s without). So the conclusion held and the
mechanism was wrong, which is the worse order: someone asked to close the gap
would find the flag accepted, see a build that looked fine, and conclude the tier
was easy to enable. Corrected in `b7e1e3a`; the reason is now what I measured.

The two real obstacles are unchanged: `docker build` has no way to declare a
dependency container, so a sidecar is not addressable from a `RUN`; and installing
a server into the stage is ~30 MB to duplicate a check the `redis` job already
forces against a pinned `redis:7.4.1-alpine`.

The gap is **bounded rather than hidden**, which is what makes it acceptable as a
limitation: the `image` job compares **test files, not test counts**. The in-image
run is `403 pass / 14 skip / 0 fail` against a host's `417 pass / 0 skip` — the
14 are exactly the live-Redis tier, expected by design. Had the comparison been
over pass counts, a correct image would fail against a correct host for the
uninteresting reason that one of them has Redis. The file count cannot differ for
that reason, so the comparison is over the thing that is actually the claim.

## The local gate, with the Redis tier forced

```
GUARD_REDIS_URL=redis://127.0.0.1:6399 GUARD_REDIS_REQUIRED=true ./bin/prime
== bun install --frozen-lockfile
== bun run typecheck
== bun test
 417 pass   0 fail   2974 expect() calls
Ran 417 tests across 17 files. [3.42s]
== prime ok (bun 1.3.12)
GATE_EXIT=0
```

**417 pass, 0 skip, 0 fail across 17 files.** The brief's target was 399 on
master. The count moved by **+18, and every one of the 18 is
`test/dockerStage.test.ts`** — verified by running that file alone (18 pass). No
existing assertion was relaxed, no count adjusted to fit, and the suite still
runs the 399 master had. In-image is the same 417 tests across the same 17 files.

---

## What I deliberately did not do

- **Did not make the test stage `COPY . .`,** which would have "fixed" the
  original finding in one line while making the check vacuous and putting the
  identity and JWKS doubles in the runtime image.
- **Did not make the CI comparison a pass-count comparison.** It would be red on a
  correct image for a correct reason, and a check that is red for uninteresting
  reasons gets ignored, which is the failure mode this packet exists to remove.
- **Did not change the Bun pin, the runtime version, or anything that changes what
  the image produces.** Filtering the 13 `src/**/*.test.ts` out of the runtime
  image would change it, so it is recorded in the README's *Not built yet* rather
  than done here.
- **Did not force the Redis tier to run in-image,** for the reasons above, and did
  not install a 30 MB server into a build stage to make a number look better.
- **Did not touch any other repository.** kit and courier were read; the kit
  findings are D1 and D2, for the manager.

## What should go into kit

1. **A test stage in all seven templates.** Today `docker build --target test`
   does not exist outside guard, so this is the whole gap (D1). The pattern to
   copy is guard's: explicit `COPY` list, `bun test` (or the language's runner)
   over the tree, never a path list.
2. **`test/dockerStage.ts` + `test/dockerStage.test.ts`, ported.** They are
   language-agnostic — stages, `COPY` chains, `.` — and drop into any service's
   `test/`. A porter supplies the stage name and the declared suite inputs.
3. **The in-image file diff, as a step in `ci.reusable.yml`.** It is the only half
   that sees `.dockerignore`, and it is the same ~15 lines for every language.
   Counting files rather than tests keeps it valid for any suite with a
   dependency-gated tier.
4. **Decide `COPY . .` in the runtime stage (D2).** Six of seven templates
   currently copy the whole context into the shipped image, test doubles included.
   Whatever the answer, it should be deliberate and should not be resolved by
   reverting to a list nobody checks.
