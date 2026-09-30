# REPORT-guard-08-edge — packet guard-08-edge

Worker `guard-08-edge`. Worktree `/Users/kaka/Code/any/moon/cafaye/guard-worker-guard-08`,
branch `worker/guard-08`, remote `git@github.com:cafaye/guard.git`.

**Three real defects found, each pinned by a test watched fail before the fix, all
fixed, gate green.** Guard is better than the packet assumed in four of the five
areas, and I have said so with evidence rather than with "I reviewed it".

---

## The gate

`mise x -- ./bin/prime` — **442 pass, 0 fail, 0 skip, 19 files**.

### Redis was provisioned, and the tier actually ran

The packet is right that a gate without Redis verifies nothing, so:

```sh
redis-server --port 6399 --daemonize yes --save '' --appendonly no \
  --dir ~/.local/state/guard-08-redis --pidfile ~/.local/state/guard-08-redis/redis.pid
redis-cli -p 6399 ping          # -> PONG
export GUARD_REDIS_URL=redis://127.0.0.1:6399
export GUARD_REDIS_REQUIRED=true
```

Evidence the tier is real and not skipped:

```
$ bun test src/middleware/rateLimitRedisLive.test.ts
 14 pass
 0 fail
```

14 pass, 0 skip. And nothing was left behind on the server:

```
$ redis-cli -p 6399 --scan --pattern 'guard:rl:*' | wc -l   ->  0
$ redis-cli -p 6399 --scan --pattern 'live-*'     | wc -l   ->  0
```

The server is on a non-default port so it cannot collide with a developer's
Redis, and the tier's `RUN` namespace is per-run UUID, so two worktrees sharing
one server cannot read each other's buckets.

### Pass and skip counted separately

```
 442 pass
 0 fail
Ran 442 tests across 19 files
```

`0 skip` is a positive claim, not an absence of evidence — it is asserted by
`test/noSkips.test.ts` (below), which fails if any test file anywhere in the
tree gains a `skip`, `skipIf`, `todo` or `only` outside a one-entry allowlist.
Before this packet that claim rested on the `redis` CI job alone.

### The gate ran under bash with `PIPESTATUS`, not `$?`

The packet calls out the zsh trap explicitly, and it is a real one: after
`./bin/prime 2>&1 | tail -12`, `$?` is `tail`'s exit code, which is always zero.

```sh
mise x -- bash -c '
set -o pipefail
export GUARD_REDIS_URL=redis://127.0.0.1:6399
export GUARD_REDIS_REQUIRED=true
./bin/prime 2>&1 | tail -12
echo "GATE_EXIT=${PIPESTATUS[0]}"
'
```

```
 442 pass
 0 fail
 3369 expect() calls
Ran 442 tests across 19 files. [1214.00ms]

== prime ok (bun 1.3.12)
GATE_EXIT=0
```

`set -o pipefail` **and** `${PIPESTATUS[0]}` — belt and braces, because
`pipefail` alone would give the pipeline's status but `[0]` is what the packet
asks for and is unambiguous.

### `GUARD_REDIS_REQUIRED` is still load-bearing

Confirmed by removing the URL while keeping the requirement:

```
$ GUARD_REDIS_REQUIRED=true bun test src/middleware/rateLimitRedisLive.test.ts
 0 pass
 1 fail
 1 error
```

A failure, not a skip. And with neither variable set, the skip is still visible
in the summary rather than hidden:

```
$ bun test src/middleware/rateLimitRedisLive.test.ts
 0 pass
 14 skip
 0 fail
```

`0 pass, 14 skip, 0 fail` — that is the shape of a green run that verified
nothing, and it is exactly what the CI job's parse and my new tripwire exist to
catch.

---

## Defect 1 — a burst of forged tokens bought one JWKS fetch each

**File:** `src/middleware/jwt.ts`, the forced-refresh budget in
`createJwtVerifier`. Pre-auth, anonymous, and free to send.

### The bug

The budget was a `forced` boolean on the cached key set, set **when the fetch
completed**:

```ts
async function load(forced: boolean): Promise<JWK[]> {
  const fetched = await fetchKeys();
  cache = { keys: fetched, fetchedAt: now(), forced };   // <-- set AFTER the await
  return fetched;
}
```

and the check that read it:

```ts
if (!fetched && cache?.forced !== true) {
  set = await load(true);
}
```

Every request already in flight when a refresh began reads `cache.forced` as
`false`, because the flag has not been written yet. So twenty-five simultaneous
requests each decide to refresh, and each refresh is a real `fetch` aimed at
identity. The source comment promised "**one** forced refresh per cache window";
under concurrency it was one per request.

The attack needs no credential. A token-shaped string with an `alg: RS256`
header and a `kid` identity does not publish is enough, and it is refused with a
`401` either way — so the cost to the attacker is zero and the cost to identity
is the traffic.

### The test, red

Added to `src/middleware/jwt.test.ts`. The existing suite already covered the
*sequential* unknown-`kid` case ("an unknown kid that stays unknown fails after
one refresh, not a loop"), which is why this was green: a loop of `await`s never
has two requests in flight at once.

```
$ bun test src/middleware/jwt.test.ts -t "burst of unknown kids"

src/middleware/jwt.test.ts:
483 |       });
484 |     }
485 |
486 |     // One cached fetch plus exactly one forced refresh, however many arrived at
487 |     // once. Anything above two is the amplifier this rule exists to prevent.
488 |     expect(identity.requests).toHaveLength(2);
                                    ^
error: expect(received).toHaveLength(expected)

Expected length: 2
Received length: 26

      at <anonymous> (/Users/kaka/Code/any/moon/cafaye/guard-worker-guard-08/src/middleware/jwt.test.ts:488:31)
(fail) key rotation > a burst of unknown kids buys one refresh, not one per request [36.19ms]

 0 pass
 56 filtered out
 1 fail
 253 expect() calls
Ran 1 test across 1 file. [417.00ms]
```

**26 requests to the JWKS endpoint where the budget is 2.** One cached fetch,
plus twenty-five unauthorised refreshes.

### The fix

The budget is now claimed **before** the await, and is a per-window number
rather than a boolean:

```ts
let window = 0;
let refreshSpentIn: number | null = null;

async function load(opening: boolean): Promise<JWK[]> {
  const fetched = await fetchKeys();
  cache = { keys: fetched, fetchedAt: now() };
  if (opening) { window += 1; refreshSpentIn = null; }
  return fetched;
}

// ...and where the budget is spent:
if (!fetched && refreshSpentIn !== window) {
  refreshSpentIn = window;          // <-- claimed before the await
  set = await load(false);
}
```

Two properties fall out of this that a boolean cannot express:

- **Claimed on decision, not on completion.** Concurrent arrivals all observe the
  claim and none of them refreshes again.
- **A window number, not a flag.** A flag cannot tell this TTL window from the
  last one, which is either why it was never cleared or why clearing it let a
  burst in again.
- **A failed refresh spends it.** `refreshSpentIn` is set before the `try`, so
  an unreachable identity is not an unlimited fetch allowance for anyone naming
  a `kid`.

### Green

```
$ bun test src/middleware/jwt.test.ts
 57 pass
 0 fail
```

Including the pre-existing sequential rotation tests — the fix did not weaken
the baseline, it strengthened a case the baseline did not have.

---

## Defect 2 — `X-Forwarded-For` accepted non-addresses as bucket identities

**File:** `src/middleware/limitKey.ts`, `addressOf`.

### The bug

The filter was a **charset**, not an address check:

```ts
const IP_LITERAL = /^[0-9a-f:.%]+$/;
// ...
return IP_LITERAL.test(bare) ? bare : null;
```

with a comment claiming:

> Only something shaped like an IP literal is accepted

`[0-9a-f:.%]+` is not that. `deadbeef`, `cafe`, `babe`, `...` and `999.1.1.1` are
all inside the character class and none of them is a host. Each one that passed
became a bucket identity, so a caller who could place an entry at the trusted hop
minted a fresh allowance per request by varying a string that was never an
address. The limiter was decorative in exactly the deployment that configures
it.

Note what the existing tests covered: whitespace, the literal word `unknown`, and
a blank hop. All three are caught by an explicit test or an emptiness check. The
*positive* filter — the thing actually standing between a caller and a fresh
bucket — had no test at all.

### The tests, red

Unit level, in `src/middleware/limitKey.test.ts`:

```
$ bun test src/middleware/limitKey.test.ts -t "not an address"

155 |   // `::` are not an address either. All three pass, and each one that passes
156 |   // becomes a bucket identity, so a caller who can put an entry in the trusted
157 |   // position mints an unlimited number of allowances by varying a string that
158 |   // is not an address at all. The rejection that stops this has to be "is this
159 |   // an address", not "does this contain no spaces".
160 |     expect(await read(1, { "x-forwarded-for": "deadbeef" })).toBe("unknown");
                                                                   ^
error: expect(received).toBe(expected)

Expected: "unknown"
Received: "deadbeef"

      at <anonymous> (.../src/middleware/limitKey.test.ts:160:62)
(fail) clientIp and the trusted proxy count > an entry that is not an address is not accepted as one either [0.47ms]
```

End to end, through the real limiter, in `src/middleware/rateLimit.test.ts` —
this is the one that matters, because it states the consequence rather than the
function:

```
$ bun test src/middleware/rateLimit.test.ts -t "forwarding header on non-addresses"

432 |
433 |     expect(statuses).toEqual([200, 200, 200, 429]);
                           ^
error: expect(received).toEqual(expected)

@@ -4,3 +4,3 @@
    200,
-   429,
+   200,
   ]

- Expected  - 1
+ Received  + 1

      at <anonymous> (.../src/middleware/rateLimit.test.ts:433:22)
(fail) key derivation, through the middleware > a caller who varies the forwarding header on non-addresses gains nothing [20.04ms]
```

**A limit of 3 that is never reached.** Four forged headers, four buckets, four
`200`s.

### The fix

`addressOf` now parses:

```ts
import { isIP } from "node:net";
// ...
return isIP(bare) === 0 ? null : bare;
```

`node:net` is a **runtime builtin**, in the same category as the `node:crypto`
SHA-256 in `./rateLimit` — not a package. `package.json` and `bun.lock` are
unchanged; I verified that below. Stated loudly here because the packet asks for
it.

`isIP` also settles the `%zone` suffix (`fe80::1%eth0`), which is why the old
charset had to allow `%` at all — a real IPv6 literal with a zone id is valid and
must be read.

### A bad fix I made first, and corrected

My first draft of the test asserted that `::` must be refused. It passed `isIP`
(which is right — `::` is the IPv6 unspecified address, a legitimately-shaped
literal), and I removed the assertion rather than weaken the filter to satisfy a
test I had written from a wrong assumption. Rejecting real addresses is the same
defect pointing the other way: it merges every client behind one proxy into one
bucket. Both directions are now pinned:

- `an entry that is not an address is not accepted as one either` — `deadbeef`,
  `abcd`, `...`, `999.1.1.1`, `1.2.3` are all refused.
- `real addresses in every shape the header carries are still read` — `203.0.113.4`,
  `203.0.113.4:44321`, `2001:db8::1`, `[2001:db8::1]:44321`, `10.0.0.1`, `::1`,
  `fe80::1%eth0` all still resolve.
- `a real address is still a real caller, after the filter is tightened`
  (`rateLimit.test.ts`) — two addresses remain two callers through the limiter.

### Green

```
$ bun test src/middleware/limitKey.test.ts src/middleware/rateLimit.test.ts
 54 pass
 0 fail
```

---

## Defect 3 — an identity 5xx was dropped with no log line at all

**File:** `src/bff/auth.ts`, `unusable()`.

### The bug

`call()` logs when the **transport** fails:

```ts
try {
  return await within(send(...), timeoutMs, ...);
} catch (error) {
  console.error("guard: identity call failed", error);
  return null;
}
```

That is the rare half. An identity that is **up and returning 500** — a broken
deploy, an OOM, a panic, which is what most dependency outages actually look
like — does not throw. The response arrives, matches none of the documented
statuses, and the handler falls through to `unusable()`, which returned a
`Problem` and nothing else.

So the browser got a `503` and guard's log said nothing at all. `unreachable()`
carries this in its own comment — *"The URL and the status that produced it are
in the log either way"* — and `unusable()` exists as a **separate** 503
precisely so an operator can tell "identity is down" from "identity answered with
rubbish". Neither was true of an upstream 5xx. That is a silent outage: every
login in a deployment failing with one status, and no signal except the browsers
of its users.

### The test, red

```
$ bun test src/edge.test.ts -t "identity 5xx is recorded"

437 |     // Recorded. The URL and the status are what makes the 503 diagnosable; the
438 |     // upstream *body* is deliberately not required, because a dependency's
439 |     // error page is exactly where a credential would be, and the rule above is
440 |     // that nothing like that is ever written down.
441 |     const line = JSON.stringify(logged);
442 |     expect(line).toContain("identity.test");
                       ^
error: expect(received).toContain(expected)

Expected to contain: "identity.test"
Received: "[]"

      at <anonymous> (.../src/edge.test.ts:442:18)
(fail) nothing a caller sends reaches a header or a log line > an identity 5xx is recorded, not silently swallowed [1.24ms]
```

**The log is `[]`.** Nothing was recorded.

### The fix

`unusable()` now writes the target URL and the status down:

```ts
function unusable(target: string, status: number, body?: unknown): Problem {
  const shape =
    body === undefined ? "no body"
    : body === null ? "not JSON"
    : typeof body === "object" ? "a JSON document"
    : typeof body;

  console.error(`guard: identity ${target} answered ${status} (${shape}), which this contract does not cover`);
  return { status: 503, code: "unavailable", detail: "the authentication service answered with something unusable" };
}
```

**Never the body.** A dependency's error page is exactly where a credential turns
up, so the line records the *shape* of the answer and not its contents. The test
asserts both halves: `identity.test` and `500` are present; `hunter2` and
`10.11.12.13` — planted in the fake's error body — are absent from the log.

### A second bug my own first fix contained

The gate output showed a line I did not expect:

```
guard: identity http://identity.test:8080/v1/me answered 200 (a JSON document), which this contract does not cover
```

Two flaws in my first version:

1. I called `jsonOf(response)` **twice** on the same response in `/auth/me` and
   `/auth/register`. A body can only be read once, so the second read returns
   `null` — and `typeof null === "object"`, so the line reported "a JSON
   document" about a response it had not read. A log line lying about the shape of
   an outage, to the operator who has just been sent to look at it.
2. `typeof null` also misreports a body that **failed to parse** as a JSON
   document, so an identity that started returning a login page would be recorded
   as "a JSON document".

Both fixed: the document is parsed once and reused, and `null` is separated from
`undefined` and from a document. Pinned by two tests —
`the recorded shape is what identity actually sent` and
`an identity answer that is not JSON is recorded as not JSON`.

I also confirmed the shape test is load-bearing by reintroducing the double read
and watching it fail, rather than trusting that it would.

### Green

```
$ bun test src/edge.test.ts src/bff/auth.test.ts
 76 pass
 0 fail
```

The full 29-case `auth.test.ts` suite passes unchanged, so the existing refusal
behaviour — a `422` still forwards field errors, a `409` still says conflict, a
`401` still says the same thing for every wrong credential, an account lockout
still forwards `Retry-After` — is untouched.

---

## Areas that were clean, and how I know

Per the packet: "If an area is clean, say what you checked and how."

### 4. The request itself — path traversal through the routing table: **clean**

The concern is a gateway whose routing is decided by string manipulation, where
`/v1/../v1/me` and `/v1/me` are the same request but reach the middleware
differently. I probed sixteen spellings against the real router before writing
any code:

```
"/v1/me"                 401      "/v1%2fme"              404
"/v1//me"                401      "/v1/%2e/me"            401
"//v1/me"                404      "/v1/me%2f"             401
"/v1/./me"               401      "/v1/me/"               401
"/v1/../v1/me"           401      "/v1/me%00"             401
"/v1/me?x=1"             401      "/V1/me"                404
"/v1/me#f"               401      "/%76%31/me"            401
"/auth/../v1/me"         401      "/v1/me;x=1"            401
"/healthz/../v1/me"      401
```

Every spelling that reaches a route is `401` without a token. Nothing normalises
into a handler while skipping the gate. This is now permanent in
`src/edge.test.ts` as `every spelling of /v1/me that reaches a route still meets
the auth gate`, plus `a traversal out of /v1 does not land on a route outside the
gate`, which asserts a traversal can never reach `/auth/login` and mint a
session cookie.

**CRLF and header injection: clean, and the reason is the runtime, not guard.**
Bun refuses to *construct* a request whose header value carries a line break:

```
TypeError: Header 'x-forwarded-for' has invalid value: '203.0.113.4
X-Injected: yes'
```

so the bytes never arrive. I assert the refusal itself rather than a filter,
because asserting a filter that does not exist is how a test becomes a claim
about nothing. The guard-side half is also asserted: `X-Forwarded-For` becomes a
SHA-256 digest inside a bucket name and never reaches a response header.

**Body size: already covered and correct.** `readBounded` enforces 4 KiB at the
*reader*, not after `request.text()`, so an unauthenticated caller never chooses
how much of the process one request holds, and a lying `Content-Length` does not
help.

**Header size:** not guard's to enforce; `Bun.serve` owns it. Noted rather than
claimed.

### 3. SSRF and open-proxy: **clean**

I checked where every outbound fetch target comes from, and proved it rather than
reading it:

- **The BFF** builds exactly one URL: `identityUrl + path`, where `path` is a
  member of a frozen four-constant map (`IDENTITY`) and `identityUrl` is validated
  at construction to be an http(s) origin with no path. `test/a body carrying
  absolute URLs reaches identity as data, never as a target` posts a body
  containing `http://169.254.169.254/latest/meta-data/…`,
  `http://127.0.0.1:6379/`, a `../..` path and a `file:///etc/passwd` href, and
  asserts exactly one call, to `http://identity.test/v1/users`, with the payload
  intact in the body where identity can validate it.
- **Headers** — `no request header can move the identity target` sends
  `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Host`,
  `X-Identity-URL` and `Referer`, all aimed at the metadata service.
- **Redirects** — `fetch` follows a 3xx by default, which is exactly why a
  redirect from identity is worth a test. `a redirect from identity is not
  followed to a re-checked target` asserts a `302` produces a `503`, **one**
  recorded call, and no `169.254.169.254` in the response.
- **The JWKS URL** is `${IDENTITY_JWKS_URL or issuer}/.well-known/jwks.json`,
  operator configuration, validated at construction. No request header or query
  parameter reaches it.

There is no route, header or query parameter in guard that reaches an outbound
fetch at all. That is the structural answer, and the tests exist so it stays
true.

### 5. What guard does on failure: **clean after Defect 3**

Before this packet, a throwing handler was already covered
(`a throwing handler is a flat JSON 500 and leaks nothing to the caller`). I
added the upstream case, which was the half that was not: an identity 500 whose
body is `Error: connect ECONNREFUSED 10.11.12.13:5432 password=hunter2` is
asserted to reach the browser as none of `10.11.12.13`, `5432`, `hunter2`,
`ECONNREFUSED`, `identity.test` — and now to reach the **log** with the URL and
status but never the body.

### 1. Token verification — algorithm pinning, key confusion, unknown `kid`, clock skew

**Clean, and already well covered.** muse-06 closed `alg: none` and the
HMAC-verified-against-the-RSA-public-key break in muse; guard was not carrying
either, and I checked rather than assumed:

- The protected header is read **before any key is fetched**
  (`decodeHeader`), and `alg` must equal the pinned `RS256` constant, so a
  rejected algorithm costs zero network. `jwtVerify` is *also* given
  `algorithms: [ALGORITHM]`, so it is pinned at both ends.
- `alg: none`, `HS256` and `ES256` are each refused by name in
  `jwt.test.ts`, and `a rejected algorithm header is refused before any key is
  fetched` asserts the zero-network property.
- Unknown `kid` fails closed: it is looked up by name, never "try every key we
  have", and one failure buys exactly one refresh (**Defect 1** above is the
  concurrency hole in that budget).
- JWKS caching **is** bounded, and the bound is the revocation window: the TTL is
  tested at its edge (`the default TTL is 300 seconds`,
  `a configured TTL is honoured`) and a retracted key is tested to keep working
  until the cache expires (`a key identity retracts keeps working until the cache
  expires`). A rotation can revoke.
- `iss`, `aud`, `exp` and a non-empty `sub` are all enforced, and the rejection
  messages are built from jose's **code** and **claim name** only — never its
  message, which quotes expected values and would be a map of the platform's
  internals.

One thing I checked and want to be honest about: **clock skew.** jose's default
`clockTolerance` is zero, so guard is strict rather than lenient here. That is
the safe direction for a security decision — a token that expired 1 second ago is
refused — and the packet asks for "a stated tolerance that is not zero-by-accident
and not an hour-by-drift". Zero is currently **unstated**, which I am flagging
rather than fixing: introducing a tolerance is a deployment decision with a real
failure mode in the other direction (a fleet-wide outage when clocks drift), and
it belongs to the packet that owns the identity contract, not to this one. It is
recorded here so the next reader knows it was looked at.

### 2. Rate limiting — the store being unreachable

**Already a defended, observable decision, and I found no defect.** A store that
throws fails **open**, and the packet asks for the trade-off to be picked,
defended, and made observable. All three are true:

- Picked and named in the source: failing closed "hands an outage in the counter
  store to every caller as a 429".
- Observable two ways: the `RateLimit-*` headers are **left off** rather than
  guessed at (a client told `RateLimit-Limit: 600` and then never refused is worse
  than one told nothing), and the store is a registered readiness probe, so
  `/readyz` reports `redis: unavailable` for exactly as long as the gap exists.
- Verified against a **real** Redis, not a transcription:
  `an unreachable server throws rather than resolving, which is what makes the
  limiter fail open` opens a port, closes it, and proves `lazyRedis().ping()`
  rejects rather than resolving — because a connection that resolved on a refused
  port would turn an outage into a limiter answering "allowed" with no error
  anywhere.

Per token / per account / per address: the key is `account > api key > address`
in one function, and the identity is **SHA-256 digested** before it reaches a
store, so an `account_id` claim — which is whatever identity chose to put there —
cannot become a Redis key, and a key that trips the charset check can no longer
fail the limiter open. The bucket is keyed on the **verified** principal and the
limiter is mounted *after* the auth gates, so an unverified claim never becomes a
key.

### What I added that is not a defect

`src/edge.test.ts`, 15 negative claims, and `test/noSkips.test.ts`.

The tripwire is worth calling out because the packet asks for it directly. It
reads the suite's own source and fails on any `skip`, `skipIf`, `todo` or `only`
outside a one-entry allowlist — because the two mechanisms that protect the Redis
tier (`GUARD_REDIS_REQUIRED` and the CI job's `0 pass` check) protect **one
file**, and a second gated tier added tomorrow would arrive with neither. I
verified the tripwire actually fires rather than trusting a green run:

```
$ cat src/tmpskip.test.ts   # describe.skip(...) and test.todo(...)
+   "src/tmpskip.test.ts uses describe.skip",
+   "src/tmpskip.test.ts uses test.todo",
(fail) the suite cannot skip itself > the only skip in the suite is the declared one
```

It names both offenders. It is built from arrays at runtime rather than written as
a regex literal, because a literal matching `\.\s*(skip|skipIf)` **matches its
own source** and would always fail for the wrong reason — a detector that cannot
detect itself is a detector that has to be quietly switched off.

---

## Constraints

| Constraint | How it was honoured |
|---|---|
| No token, cookie or JWT in any output | No token, cookie or JWT appears in this report. The one token-shaped string is `not-a-real-token` in a test, and every key in `src/edge.test.ts` and `test/noSkips.test.ts` is generated in-process by `testKey()` at test time. |
| No sleeps | None added. The burst test uses `Promise.all`, not a delay; clocks are injected (`now`) as the existing suite does. |
| No raised retries | None. |
| No loosened assertions | None. Baseline went **417 pass → 442 pass**, 0 fail throughout. The pre-existing JWT, limitKey, rateLimit, auth, index, limits, problem and redis suites all pass unmodified. |
| No network in the unit tier | `src/edge.test.ts` uses an injected `fetch` and an in-process key pair. No new test opens a socket except the pre-existing live-Redis tier, which is env-gated. |
| Redis tier actually ran | 14 pass, 0 skip; provision and evidence above. |
| No dependency added | `node:net` is a **runtime builtin**, same category as the existing `node:crypto`. `package.json` and `bun.lock` are byte-identical — `bun install --frozen-lockfile` passes and the `git diff --exit-code -- bun.lock` that CI runs has nothing to see. |
| `ci.yml` unchanged | Untouched. |
| Nothing crossed a service boundary | Defects 1–3 are all in guard's own source. No `identity`, `muse` or `core` file was read for a fix or modified. |
| No test skipped, deleted or pending | 0 skip, asserted by the new tripwire. |
| No force-push | Not used; the branch is built by ordinary commits on top of `fa84fb7`. |

### One judgement call, stated

I did **not** add a JWKS `clockTolerance`. jose's default is zero, so a token one
second expired is refused. The packet asks for "a stated tolerance that is not
zero-by-accident and not an hour-by-drift", and the honest position is that guard
currently has no *stated* tolerance at all — it inherits jose's. Widening it is a
deployment decision whose failure mode is a fleet-wide outage on clock drift, and
it belongs to the packet that owns the identity contract. Recorded rather than
silently changed; if the reviewer disagrees, it is a two-line change and a
documented one.

---

## Files changed

```
src/middleware/jwt.ts            refresh budget claimed before the fetch; window number
src/middleware/limitKey.ts       isIP instead of a character class  (Defect 2)
src/bff/auth.ts                  unusable() records URL + status, never the body  (Defect 3)
src/edge.test.ts                 NEW — 13 edge claims under attack
test/noSkips.test.ts             NEW — the suite cannot skip itself
src/middleware/jwt.test.ts       + the burst test (Defect 1)
src/middleware/limitKey.test.ts  + non-addresses refused, real addresses still read (Defect 2)
src/middleware/rateLimit.test.ts + the end-to-end bypass proof (Defect 2)
AGENTS.md  README.md  CHANGELOG.md
```

`package.json`, `bun.lock`, `ci.yml`, `Dockerfile`, `openapi/` and every other
service untouched.