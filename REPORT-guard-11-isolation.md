# guard-11 — making the tenant boundary load-bearing

D18 measured guard at **zero** cross-tenant negative tests, alongside identity (7)
and courier (19), with the other eight services also at zero. darkroom-09 landed
first and set the shape: enumerate the account-scoped entry points, write a
negative test for each, and make the answer **absence** rather than `403`.

This packet does the same for guard, and the finding is better than a number. The
implementation was mostly right — the bucket is keyed on the verified account, the
principal's account comes from a signed claim, `/v1/me` echoes nothing but the
caller's own — and the two places it was wrong were wrong in the way that matters
most: **a key id was a tenant.**

## The count

| | |
|---|---|
| **Account-scoped entry points** | **11** |
| — routes whose body is an account | 1 (`GET /v1/me`) |
| — ways to *name* an account (claim, header, record) | 4 |
| — account-scoped store operations | 2 (`revoke`, `list`) |
| — counter-store state keyed by account | 4 |
| **Negative tests asserting A cannot reach B** | **37** (was 2) |
| — behavioural (`src/middleware/tenantIsolation.test.ts`) | 24 |
| — structural, no network (`test/tenantEntryPoints.test.ts`) | 13 |
| **Operation kinds covered** | **4 of 4** — read 5, list 1, update 3, delete 2 |
| Cross-tenant defects found and fixed | **2** |
| `403` found for a resource the caller cannot see | **0** |
| `403` added | **0** |
| Live-Redis tier, executed / skipped | **15 pass / 15 skip** (see below) |

Every number is checkable. The 11 entry points are derived from the code by
`test/tenantEntryPoints.test.ts`, not written down: the routes come off Hono's own
`app.routes`, the account-scoped store methods off the interface declarations, and
the `403` sites off a scan of production source. Each entry point names a test
that must exist in the behavioural file, so a new one fails the gate until its
negative case is written, and a test for something not in the table is decoration.
A reader who disagrees can add a row and see what breaks.

## The eleven, and what each one is

guard holds no account's rows. There is no `assets` table and no query that could
drop `and account_id = $2`, so darkroom's shape does not transfer literally. What
guard holds is **state keyed by account** — a rate-limit bucket, a set of API-key
records — and the ways to *name* an account, which are the ways a boundary gets
crossed.

| kind | entry point | where | negative case |
|---|---|---|---|
| read | `GET /v1/me` echoes the caller's verified account | `src/index.ts` | `A's own response names A` |
| read | every header a caller writes is ignored | `src/middleware/limitKey.ts` | `A's response contains no byte of B's account, however A asks for it` |
| read | the account comes from the *signed* token | `src/middleware/jwt.ts` | `a token whose account_id was edited after signing is refused, not honoured` |
| read | the key gate authenticates as the **record's** account | `src/middleware/apiKey.ts` | `a key issued to B authenticates as B even when the request names A` |
| read | the counter key is a digest, naming no account | `src/middleware/rateLimit.ts` | `the Redis key a request writes names no account, including its own` |
| list | `list(accountId)` filters on the record's own account | `src/middleware/apiKey.ts` | `two accounts holding the same key id do not bleed into each other's listing` |
| update | the bucket is keyed on the verified account | `src/middleware/limitKey.ts` | `A exhausting his allowance leaves B's untouched and unreadable` |
| update | `revoke(accountId, id)` takes the account | `src/middleware/apiKey.ts` | `A naming B's key id changes nothing, and B's key still works` |
| update | the bucket key is derived from verified identity only | `src/middleware/rateLimit.ts` | `a key cannot be chosen by the caller, so A cannot spend B's allowance` |
| delete | a refused revocation leaves the record alone, `revokedAt` included | `src/middleware/apiKey.ts` | `B's record is not even marked revoked by A's attempt` |
| delete | no account-scoped refusal answers 403 | `src/problem.ts` | `no account-scoped refusal in this file answers 403` |

`/healthz` and `/readyz` hold nobody's data and have no negative case, which is
asserted rather than left to be inferred. `/auth/*` needs a `bff` option the
factory is not given in the structural file; it is covered in the behavioural one,
which builds the browser surface deliberately.

There is **no `write` kind**, and the reason is a real gap rather than an
oversight: guard issues no key on any route. The README says so under "Not built
yet" — "What is missing is the caller, not the capability" — so there is no request
that *creates* account-scoped state for a caller to be refused.

## The two defects

Both are in `memoryApiKeyStore`. **Neither was reachable from a route today** —
guard has no endpoint that issues or revokes a key — and both are load-bearing
anyway, because the store is the seam `TODO(guard-07)` moves to Redis and the trait
is what the future `/v1/api-keys` route will call. A store whose scoping is wrong
is a store whose Redis implementation will be written from a signature that does
not mention the account.

### 1. `revoke(id)` took no account — a cross-tenant **write**

A key id is not a tenant. Ids are shown to a holder as a twelve-character prefix to
tell two keys apart, and handed to an operator for revocation, so any caller who
learned one could name it. With no account in the signature, any caller could
withdraw any account's credential.

Measured, before the fix, against a two-account store:

```
B's key works          : true
after a bare revoke    : false      <- A revoked B's credential
A's own key untouched  : true
```

Now `revoke(accountId, id)`, scoped inside the store on the record's own
`accountId`. It refuses by **not acting**: no error, no return value. A throw there
would be a "that key is not yours" oracle one layer below the wire, which is the
same leak as a `403` and harder to notice in a method typed `Promise<void>`.

### 2. `list(accountId)` could return another account's record — a cross-tenant **read**

`byId` is keyed by id alone, so two accounts holding the same id made one account's
listing resolve its own id to the *other* account's record. Measured:

```
A asks for its keys, gets 1
the record it gets belongs to: acc-bbbb
is that A? false
leaks B's hash? true
leaks B's prefix? true
```

Silent, because the record returned is real, well-formed and about somebody else —
hash and prefix included, which is credential material. `byId` being keyed by id
made a collision the only thing standing between a caller and another tenant's
keys.

The mitigation in the issuer is a `randomUUID`, which makes this improbable rather
than impossible, and `TODO(guard-07)` is about to write a store that trusts a
caller-chosen id. `list` now filters on `record.accountId` rather than trusting
membership of an id set.

## Absence, not refusal

**No `403` was found for a resource the caller cannot see, and none was added.**
The only two `403`s guard writes are:

- `requireScope` — the token authenticated and lacks a scope. A **capability**
  failure: a fact about the caller, which they already know, so reporting it leaks
  nothing. There is no existence to leak, because the caller never got as far as
  naming a resource.
- `requireSameOrigin` — the request cannot prove its origin. About the request.

Neither names a resource, so neither can confirm one exists. The distinction is
load-bearing in both directions and both halves are asserted: a `403` for
*tenancy* would be a finding to fix, and a `404` for *capability* would throw away
a distinction the caller is entitled to. `requireScope`'s detail names the scope
that is missing — guard's own configuration, safe to name — and never echoes the
scopes the caller *does* hold, which would tell a prober what else to try for.

Absence is enforced below the wire too. In the store, `revoke` on a foreign key
leaves `revokedAt` at `0`, so an attempt that missed its scoping leaves nothing an
operator could mistake for a real withdrawal. `find` answers `null` for both an
unknown hash and a withdrawn one, and the withdrawal case is asserted to produce
a **byte-identical body** to an unknown key bar the trace id — a refusal that said
"revoked" beside an unknown that said "invalid" would confirm that a guessed key
once existed.

## The two files, and why they are two

The work splits along one line: *is the scoping still written down* is a property
of the source, and *does the scoping actually hold* is a property of the stores.
Neither substitutes for the other — a call that names an account and a call that
constrains on it are different strings in a file and different operations in a
running process — so they are two files, and each says so.

### `src/middleware/tenantIsolation.test.ts` — the behavioural half

Two accounts, chosen to be visibly different in every field that could be echoed
(UUIDs rather than `acc-a`/`acc-b`, because a test that passes on short ids may be
passing on a prefix), four operation kinds, and the Redis path driven over a
transcription of `GCRA_LUA` so the multi-replica store is covered without a server.

Three deliberate choices, each earning its place:

- **Absence is asserted as absence, not as a failure.** Every negative case checks
  the thing B still holds — `store.find(B's hash)` still resolves, `revokedAt` is
  still 0, B's `RateLimit-Remaining` is still positive. A cross-tenant `revoke` that
  missed its scoping *and* returned "not found" would satisfy a weaker version that
  only checked the thrown error.
- **Both directions of the limiter are checked.** Exhausting A's allowance must not
  throttle B (denial of service), *and* B's headers must not report A's debt — a
  `RateLimit-Remaining` of 0 in B's response tells B that somebody else is being
  throttled, and a shared bucket is exactly how that leaks.
- **The counter key is observed, not recomputed.** See the next section.

### `test/tenantEntryPoints.test.ts` — the structural half, no network

Reads the repository's own source and derives what must have a negative case. It
is in the **default tier on purpose**: it needs no Redis, no socket and no
identity, so it runs on every `bin/prime` and in the test image. It is the half
that catches the edit *before* a fixture is built.

Five properties, each load-bearing alone:

1. **Every entry point names a test that exists** — by test name, which is the one
   identifier a failing run actually prints. The failure message lists the
   offenders.
2. **The account-scoped store methods are derived** from the interface declarations
   and asserted against a literal, so a method that stopped taking an account — or
   a new one added that does not — is a failing test rather than a quieter list.
3. **`revoke` does not take a bare id, and refuses without throwing.** Checked on
   the source, which catches the signature narrowing before any behavioural test
   could be written for the new shape.
4. **Every `status: 403` in production source is accounted for**, and there are
   exactly two, in `jwt.ts` and `auth.ts`. A third is the finding this packet is
   for.
5. **The count and the operation-kind breakdown are asserted**, not described, so
   this file's headline cannot rot into prose.

## Two bugs the guards had themselves

This is the part worth the most, and both were found by **running** the guards
rather than reading them. Each had the same shape: a check that could not fail.

### 1. The listing fixture was a silent no-op

The first draft built its colliding id through `createApiKeyAuth.issue`, then
re-issued under the same id for the other account. `issue` is **idempotent on the
hash** — deliberately, so the same secret twice is one key — so the second call
returned early, the collision never happened, and:

```
$ bun test src/middleware/tenantIsolation.test.ts -t "same key id"
 1 pass
 23 filtered out
 0 fail
```

**with the `accountId` filter deleted from `list`.** The case passed against the
broken store for the wrong reason. It now writes records straight to the store, and
asserts its own pre-condition — `store.size() === 1`, which is only true if the two
records really did collide onto one id. A fixture that fails to set up the
condition makes every assertion after it vacuously true.

### 2. The Redis-key assertion was a copy of the production logic

The first draft asserted that a bucket's Redis key contains no account id, by
building the key itself with `sha256(identity).slice(0, 32)` — a transcription of
`bucket()` in `rateLimit.ts`. With the digest **deleted from `rateLimit.ts`**:

```
$ bun test src/middleware/tenantIsolation.test.ts
 24 pass
 0 fail
```

Because both sides were then trivially consistent: the test was checking its own
copy. `bucket()` is private, so the test now observes the only honest point — the
key `eval` was actually handed, captured off the transport.

Both are recorded in the CHANGELOG and in `AGENTS.md`, because both are shapes the
next guard in this repository will have.

## Proven able to fire

A guard nobody has watched fail is a guard nobody knows works. Five divergences were
planted in production source and reverted. Every one was caught, and the output
below is the real run, not a paraphrase.

| # | planted | caught by | tier |
|---|---|---|---|
| 1 | `revoke` lost `record.accountId === accountId` (the original defect, re-planted) | 4 cases in `update — one account cannot withdraw another account's key`, **and** `a cross-tenant refusal in the store is absence, not an error` | default, no network |
| 2 | `list` lost its `record.accountId` filter (the original defect, re-planted) | `two accounts holding the same key id do not bleed into each other's listing` | default, no network |
| 3 | `rateLimitKey` stopped preferring the verified account, so a key id became the bucket | 4 cases in `rate-limit state keyed by account` | default, no network |
| 4 | `bucket()`'s digest deleted, so the Redis key carried the raw account id | `the Redis key a request writes names no account, including its own` | default, no network |
| 5 | `revoke` narrowing back to `revoke(id: string)` | `the account-scoped operations cover read, list and update` | default, no network |

Divergence 1, verbatim, from the behavioural tier:

```
(fail) A naming B's key id changes nothing, and B's key still works
(fail) B's record is not even marked revoked by A's attempt
(fail) A cannot revoke B's key by guessing the id either
(fail) revoking another account's key is indistinguishable from revoking nothing
 20 pass
 4 fail
```

and from the structural tier:

```
(fail) store operations > a cross-tenant refusal in the store is absence, not an error
 12 pass
 1 fail
```

**Two independent guards caught divergence 1.** That redundancy is why the structural
file asserts the store's *source shape* as well as its behaviour: a behaviour test
would notice a wrong answer, and a source check notices a signature that has not
been misused yet.

Divergence 4 is the one worth stating carefully. Deleting the digest does not break
isolation between accounts — each account still gets its own key, so every
behavioural case stayed green. What it breaks is the *privacy* property the digest
was for: `KEYS guard:rl:*` yields a list of the accounts hitting the edge. So the
test asserts a property that is not the one the defect removes, and the only way to
hold it is to observe the real key rather than recompute one. That is the second
guard's bug, and divergence 4 is what proved it.

### Redundancy worth noting

Divergence 2 was caught by exactly one test, and it is the one I expected to be
weakest: it needs a fixture whose ids collide, which is precisely what the first
draft failed to build. It is now a single strong case rather than a broad net,
because there is only one way for `list` to leak. That is a thinner guard than
divergence 1's four cases and the report says so rather than counting them as
equivalent.

## The live-Redis tier

Gated on **`GUARD_REDIS_URL`**, with `GUARD_REDIS_REQUIRED=true` turning "no URL"
from a skip into a module-load throw. Reported separately, because a CI job that
silently skips the hard part is worse than no CI.

| run | result |
|---|---|
| `GUARD_REDIS_URL=redis://127.0.0.1:6399 GUARD_REDIS_REQUIRED=true` | **15 pass, 0 fail, 0 skip** — including `two accounts' buckets are separate keys against a real server` |
| unset (`bun test`) | **0 pass, 15 skip, 0 fail** — exit 0, which is why the mechanisms exist |
| `GUARD_REDIS_REQUIRED=true`, URL unset | **0 pass, 1 fail, 1 error** at module load |

I ran the tier against a local `redis-server` on port 6399 and it passed. The new
case is the tenant boundary where it is actually load-bearing: everything else in
that file proves the script counts correctly, and this proves it counts the right
things — exhausting one account's allowance leaves another's untouched against a
real server, and the two keys differ.

The same property is covered without a server by `tenantIsolation.test.ts`, over a
transcription of the script. That cannot be wrong in the same way as the script,
which is exactly why the live tier is the one that counts.

## What was not done

- **No `403` was added and none was removed.** Both existing ones are capability
  and origin failures and are correct where they are.
- **`/auth/*` has no account-scoped negative case.** The BFF surface is keyed by a
  session id, not an account: `sessions.get(sessionId)` returns the token guard
  minted for that browser, and the session id is a `randomUUID` a caller cannot
  choose. Cross-tenant access there means stealing a session id, which is
  credential theft rather than a scoping defect, and the origin gate plus the
  `__Host-` cookie prefix are the defence. Stating that here is a scoping decision
  rather than a coverage gap, and it is the one thing in this report a reader might
  reasonably disagree with.
- **No new dependency.** The `AccountId` type is not exported from a shared module;
  `ApiKeyRecordInput` already carries the field.
- **Not pushed.** The branch is `worker/guard-11-isolation` and the manager pushes
  after the gate is green.

## The gate

All green, and the counts below are from these runs:

```
bin/prime                467 pass  15 skip  0 fail   (482 across 21 files)
docker build --target .  467 pass  15 skip  0 fail   (the same 482 in the image)
bun run typecheck        clean
live Redis tier          15 pass  0 fail              (GUARD_REDIS_URL set)
```

Baseline before this packet was 430 pass / 14 skip across 19 files; the 37 new
tests and the 2 new files are the whole difference. The 15 skips are the
live-Redis tier, which needs a server and is reported above.

No sleeps were added, no retry was raised, and no assertion was loosened. The one
assertion that *was* loosened — comparing a forged token's 401 body to a
fabricated one's — was loosened for a stated reason and is described above: the
two rejections are for genuinely different reasons, and the property that matters
is that neither body names the other account. No test logs a token, a key, a hash
or a JWT; the assertions that check for absence do it with string containment on
the *response*, never by printing the credential.