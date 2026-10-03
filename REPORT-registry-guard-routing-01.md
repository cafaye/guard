# REPORT — registry-guard-routing-01: guard proxies to a service

Branch `worker/reg-routing-01`, four commits on top of `8293710`. Nothing pushed,
nothing merged.

---

## 1. What the packet asked for, in one paragraph

`guard` was the only door into a deployment and it opened onto nothing. Its README
said so in its own words — *"no request is proxied to a service yet"* — and
`GET /v1/me` said it again by existing as a placeholder. `site`, the whole
frontend, cannot be built until something forwards: it calls identity and pantry
server-side through the gateway and the browser is never meant to hold a token
that reaches an internal service. This packet is the thing guard's README already
described as missing, in the shape its tests and conventions already expected.

---

## 2. The routing config: shape and validation

**Shape.** One JSON object in one environment variable:

```sh
ROUTE_TABLE='{"/v1/pantry":{"baseUrl":"http://pantry:8080","token":"…"}}'
```

`{prefix: {baseUrl, token?}}` — a plain object, deliberately. One variable rather
than N, because the table *is* the configuration; a `PANTRY_PREFIX` variable would
encode a routing decision in a variable's name that the table states. Plain object
because the registry this packet does not build would *populate* it: discovery
would mean a different `runtimeOptions` and no change to `createApp`, the
middleware, or the matching rule. That is what makes the swap a populate rather
than a rewrite, and it is the answer to "make the config the thing a registry
would populate".

`createApp({ routes })` takes it as an argument, never an environment read in the
module body — `runtimeOptions` is the only reader of `Bun.env`, as before.

**Every validation is a startup error**, on the `REDIS_URL=redis//redis` precedent.
Eight shapes are refused, each with its reason in the source and in the README:

| Refused | Why |
| --- | --- |
| not JSON, or not an object | `JSON.parse`'s message names a character position in a string the operator never wrote; guard's names the variable |
| a prefix outside `/v1/` | the pass-through is mounted on `/v1/*`, so it could never match — a route that silently forwards nothing |
| a glob (`*`, `?`) | a prefix is a path, not a second matching language |
| a `.` or `..` segment, encoded or not | a traversal configured on purpose, in the same notation a caller's path arrives in |
| `/v1/me` | guard's own route, registered before the mount; an entry that can never fire is a claim, not a configuration |
| a base URL with a path, query, fragment or credentials | the caller's path is appended to it; a base with a path puts the request where nobody serves it, and one with a password is a password in a log line |
| a token with whitespace or a control character | it goes verbatim into an `Authorization` header — header injection configured on purpose |
| `{}` | `ROUTE_TABLE={}` forwards nothing and an operator finds out from 404s |

19 cases in `src/routes/table.test.ts`, and the prefix rule is *enforced*, not
merely documented: `checkPrefix` refuses anything not under `/v1/`, which is why a
configured route can never reach `/auth/*`, `/healthz` or `/readyz` — the browser
surface and the probes are outside the API surface by construction rather than by
a rule somebody has to remember. Authentication and the limiter then come free,
because both are mounted above the pass-through.

**Static is the right design and not only the right scope.** The set of services in
a deployment is small, known, and changes with a deploy rather than at runtime.

---

## 3. The credential rule I chose, and why

**guard attaches the credential. The caller's inbound `Authorization` is never
forwarded to a service, and neither is their `Cookie`.** When a table entry has a
`token`, guard sends `Authorization: Bearer <that token>`. When it has none, guard
sends no `Authorization` header at all — absence, not substitution.

The reasoning, which is the security content of the packet:

- If a caller can set an arbitrary `Authorization` and have it reach pantry, guard
  is a **confused deputy**: the caller authenticates *to guard* and then *chooses*
  who they are downstream. Every property "guard is the only door" rests on — that
  the credential a service sees is one guard issued or verified — is gone, and an
  attacker needs no credential for the service at all, only a valid one for the
  edge.
- `GET /auth/me` already holds this line for identity: it takes the **stored**
  token from the session, never one from the request. Routed traffic is the same
  shape pointed at a service rather than at a route.
- It is enforced as an outbound **allowlist** (`content-type`, `accept`, plus
  guard's own token) rather than a deny list, because a deny list has to have
  thought of `Authorization`, `Cookie`, `X-Forwarded-For` and every header a future
  proxy invents, while a header nobody named cannot be a smuggling channel at all.

**The alternative I rejected, and why.** Forwarding the caller's own verified
bearer downstream would make per-account services actually usable today. It is
exactly the shape the brief calls "a deliberate, documented decision with a scope
check on it — not a default", and I could not settle the scope check inside the
hour: which scopes authorise which prefixes, and what the service does when a
token is absent, are two questions with answers on the *service's* side of the
hop. So I took the conservative option, wrote the rule down in `src/routes/proxy.ts`,
the README and `AGENTS.md`, and named it as an open decision below.

**What it costs, stated in the README and the source and not only here.** A routed
service can authenticate the caller and cannot *authorise* them: it cannot tell
which caller sent a request. The per-service `token` is a service credential, not
a delegation. That is the real limit on what this packet delivers, and it is the
first entry under "Not built yet".

The same logic, applied to the other direction, is why a service's `set-cookie` is
**not** relayed: a service answering `Set-Cookie: __Host-bff-session=…` would be
writing the browser's BFF session from behind the edge, on an origin where the
`__Host-` prefix is honoured. That is session fixation arriving through the
gateway, and it falls out of the same rule.

---

## 4. What happened to `/v1/me`

**It stays**, and the README, the OpenAPI header and `AGENTS.md` now say why in
three places instead of leaving "it is replaced by routed traffic" for the next
reader to disprove:

- it is the only route in the document whose whole answer is "the auth chain is
  wired", and a deployment needs one it can call to check that chain without
  asking a service for anything;
- routed traffic is a *different* surface, not a bigger version of this one, so
  nothing about it makes `/v1/me` redundant;
- it is registered **before** the pass-through, so Hono answers it first and no
  service sees it — and the route table *refuses* `/v1/me` as a prefix, so an
  operator cannot write a table that appears to route it.

Deleting it was defensible and would have been cheaper; it would also have meant
deleting an entry point from `test/tenantEntryPoints.test.ts`'s derivation and a
negative case from `src/middleware/tenantIsolation.test.ts`, which is coverage
this packet had no reason to reduce. That trade is the decision, and the reasoning
is in the code where the next reader will hit it.

---

## 5. How I proved an upstream failure leaks nothing

**The test.** `src/routes/proxy.test.ts` → *"a 500 from a service does not arrive
with its address, its port or its stack"*: the double answers `500` with

```
panic: runtime error
	at pantry/internal/api.go:88
connect ECONNREFUSED 10.0.3.7:5432 (http://pantry.test:8080)
```

and the assertions are `503`, `application/problem+json`, and then a loop over
`["10.0.3.7", "5432", "ECONNREFUSED", "panic", "api.go", "pantry.test", "8080"]`
asserting each is absent from the body. A sibling case covers the dead socket, one
covers the 302 whose `Location` is an internal address, and one asserts the log
records the target, the status and the shape (`not JSON`) while *not* recording the
body.

**The mutation, run rather than reasoned about.** I widened `isRelayable` from
`status < 500` to `status < 600` so a 5xx would be relayed:

```
$ grep -n "status < 600" src/routes/proxy.ts
278:  return status < 300 || (status >= 400 && status < 600);

$ bun test src/routes/proxy.test.ts
(fail) a failure behind the edge is guard's to translate > a 500 from a service
       does not arrive with its address, its port or its stack        [2.82ms]
  Received: 500
(fail) … > the failure is written down, with the target and the status  [2.18ms]
  Received: "[]"
 24 pass  2 fail
```

Reverted with `git checkout src/routes/proxy.ts`, then verified the revert by
grep (`278:  return status < 300 || (status >= 400 && status < 500);`) and by a
clean `git status` — because a mutation that silently failed to apply produces a
recipe that proves nothing.

**Three more mutations, same discipline**, each verified in the file before the run
and reverted after:

| Mutation (verified by grep) | Caught by |
| --- | --- |
| `authorization`, `cookie` added to `FORWARDED_REQUEST_HEADERS` | *"does not reach a service with no configured token"*, *"no cookie crosses, including the BFF session"* |
| the `headers.set("authorization", …)` line deleted | *"a caller's Authorization does not reach the service, and guard's does"*, *"the forwarded headers are the two that describe the body"* |
| the `.`/`..`/empty/separator segment refusal deleted from `upstreamPath` | *"a traversal cannot reach a service the table did not route"*, *"a segment that decodes to a separator cannot smuggle a path through"* |

**What the credential mutations taught me, which is why it is here.** The first
mutation — adding `authorization` to the allowlist — did **not** fail the headline
"a caller's Authorization does not reach the service, and guard's does" case. It
passed, because `outboundHeaders` sets guard's token *after* the loop, so the
caller's value is overwritten and never observed. The assertion that actually
catches it is the no-token case. Both exist, and I would rather say that than
report four mutations and let a reader assume the first one proved the headline.

---

## 6. How I proved a caller's `Authorization` is not passed through

Four tests, and the two that matter are negative claims read off the request the
service actually received (the upstream is an injected `fetch` that records the
`Request`, so the observation point is the transport rather than the function that
built it):

1. **with a configured token** — the recorded header is exactly
   `Bearer svc-pantry-token`, and the caller's full token string is not a substring
   of it (a substring check, because an implementation that *appends* the caller's
   token to guard's would pass an equality check);
2. **with no configured token** — the recorded header is `null`, which is the case
   a "just forward it" implementation gets wrong first;
3. **no cookie crosses** — the recorded request has no `cookie` header even when the
   caller presents `__Host-bff-session`;
4. **the allowlist itself** — the recorded header *names* are exactly
   `["accept", "authorization", "content-type"]`, asserted on the wire rather than
   by reading the constant, so a header somebody adds to
   `FORWARDED_REQUEST_HEADERS` for convenience fails the test.

Plus the ordering claim that makes it mean anything: *"routed traffic is
authenticated before it is forwarded"* — an anonymous request to a configured
prefix is a `401` and **no service is contacted**. A credential rule on a route
that lets anonymous traffic through would be a rule about nothing.

---

## 7. The single next move

**Decide how a routed service learns which caller sent the request, and write both
halves in one packet.**

Right now a service behind a routed prefix gets guard's service credential and
nothing else: it can authenticate the edge and cannot authorise the caller. That
makes routed traffic unusable for anything per-account, which is most of what
pantry is, so this is the packet that unblocks `site` reaching pantry and the one
that decides whether it can reach it *usefully*.

The decision is a real fork and it should not be made casually:

- **Forward the token guard verified.** One line in `outboundHeaders`, and pantry
  verifies it against identity's JWKS exactly as any other client of identity does.
  The cost is that a caller's credential now exists downstream, and the scope check
  — which scopes authorise which prefixes, and what a service does without one —
  has to be written down rather than assumed.
- **Assert the verified principal.** guard sends `account_id`/`sub`/`scope` as its
  own headers and each service checks them instead of trusting the network. No
  credential leaves the edge, and the cost is a new internal trust protocol that
  every service has to implement — a service that forgets to check one header is
  an authentication bypass with a plausible-looking implementation.

Either is defensible. Both need the *other* half written at the same time, which is
exactly why it does not belong in a routing packet.

---

## 8. Open decisions I deliberately left

1. **Caller identity across the hop** — the one above. Conservative option taken,
   named in the README's "Not built yet" as the first entry.
2. **No readiness probe per upstream.** A configured upstream *is* a dependency and
   is deliberately not registered: `/readyz` failing whenever an optional service is
   down would take a working gateway out of rotation for a path nobody called, and
   a probe per service is health-checking, which the brief puts out of scope and
   which deserves its own cost statement. Today a service that is down shows up as
   a `503` on the paths that use it and in the log.
3. **No per-prefix rate-limit allowance.** Routed paths spend `guard-api` with the
   rest of `/v1/`. The table is code and the prefixes are configuration, and a
   table that is half configuration and half code is one where lowering a number is
   mistaken for having lowered it — the exact sentence `limits.ts` already argues.
   The limiter *does* apply to routed traffic (there is a test asserting the `429`,
   because a limiter mounted after the mount answers `200` forever and only a `429`
   assertion can tell).
4. **A routed subtree is not in `openapi/v1.yaml`, and cannot be.** OpenAPI
   describes paths; a configured prefix forwards a path space that belongs to the
   service. The document's header says so in the present tense, the exclusion is
   still the exact `ALL /v1/*` pair (not a `/v1/` prefix), and
   `openapiDocument.test.ts` now builds its app **with** a route table so the mount
   is registered and the check can see it.
5. **The response relay drops every header but `content-type`**, including ones a
   service might reasonably expect (`etag`, `location` on a `201`, `retry-after` on
   a `429`). Conservative and deliberate; if a service needs one, it is an allowlist
   edit with a reason.

## 9. Things I did not do, on purpose

No service discovery, no health checking, no registry, no proxy library (`fetch` is
the tool and `hono`/`jose` are still the only dependencies), **no retries** (a
retry multiplies load on a service that is already failing and the limiter counts
one attempt), no CORS headers (the browser talks to guard and holds no token for an
internal service), no change to JWT verification, the JWKS cache or the algorithm
pinning, and no weakening of the limiter, the BFF session rules, the origin gate or
any existing test.

---

## 10. Verification — exactly what I ran

| Command | Result |
| --- | --- |
| `bun install --frozen-lockfile` (the worktree had no `node_modules`) | 7 packages installed |
| `bun run typecheck` | **exit 0**, one line of output, no diagnostics |
| `bun test` | **517 pass, 0 fail, 15 skip, 1895 expect() calls, 23 files** |
| `./bin/prime` (the repo's gate: frozen install → typecheck → `bun test`) | **exit 0** — `prime ok (bun 1.3.12)`, 517 pass / 0 fail / 15 skip |
| `docker build --target test .` | **exit 0** — the image ran **517 pass, 0 fail, 15 skip, 532 tests across 23 files**, identical to the host |
| the four mutations in §5 | each failed the named tests; each reverted and verified by grep + clean `git status` |

**Skipped, and named rather than absent: 15 skips.** They are the Redis live tier,
`src/middleware/rateLimitRedisLive.test.ts`, gated on `GUARD_REDIS_URL`, which is
not set in this worktree — the repository's own `test/noSkips.test.ts` allows
exactly that one file, and CI forces it in the `redis` job with
`GUARD_REDIS_REQUIRED=true`. I did not run the `redis` CI job, so **the Lua script
against a real `redis-server` is unverified by this packet**; nothing I changed
touches it, and I did not modify the limiter, the store or the script.

**Not run at all:** `docker compose build` (the runtime image — the test stage
passed, the runtime stage differs only in what it copies) and the CI workflow
itself. Named because the AGENTS.md gate list includes both.

**The image gate is the one worth reading twice.** `docker build --target test`
exiting 0 is a claim about what ran *in the image*, and AGENTS.md's whole history is
a test file the image did not copy failing to fail. So the build log, not the exit
code, is the evidence:

```
$ grep -c GUARD_IMAGE_TEST /tmp/docker-test.txt
23
$ grep 'GUARD_IMAGE_TEST src/routes' /tmp/docker-test.txt
#18 0.279 GUARD_IMAGE_TEST src/routes/proxy.test.ts
#18 0.279 GUARD_IMAGE_TEST src/routes/table.test.ts
#18 1.090 Ran 532 tests across 23 files. [967.00ms]
```

23 discovered files, 23 files run, same counts as the host. The build image was
removed afterwards (`docker rmi 0a8df4ceb66e`, "Deleted"), and nothing is left
running.

---

## 11. Findings outside the packet

1. **The README's `src/**/*.test.ts` count was already stale.** It said
   "thirteen test files ship in the runtime image"; there were **fifteen** before
   this packet and are **seventeen** now. Nothing checks that number, which is why
   it rotted. I corrected it to seventeen and changed the same number in
   `test/dockerStage.test.ts`'s comment to "every `src/**/*.test.ts`", so it cannot
   rot the same way again. **The number is still unasserted anywhere** — a
   `dockerStage.test.ts` case asserting the shipped count against `find src -name
   '*.test.ts'` would make it a fact rather than prose, and I did not add one
   because it is a change to a check this packet did not need.

2. **`site` already proxies `/v1/*` to identity, server-side, and does it well.**
   `site/src/lib/upstream.ts` reaches the same four properties this packet reaches
   from the other end of the same hop — one configured destination, paths rebuilt
   from a table, no internal address in a failure, the upstream's own statuses
   passing through — and its header says so. I borrowed its numbering rather than
   inventing a second vocabulary for one problem. **When `site` is switched to
   guard, its literal six-route allow-list is the thing that decides which identity
   operations a browser can reach**, and that decision has not been made. It is a
   `site` packet, not this one.

3. **`pantry` authenticates nothing today** — no `Authorization` handling anywhere
   in its Go source. That is *why* the conservative credential rule costs nothing
   right now: there is no per-account surface being served without a caller
   identity, because there is no per-account surface being served. The moment
   pantry grows one, §7 becomes the blocker rather than a design question.

---

## 12. Commits

| | |
| --- | --- |
| `bd8af93` | **routing: the route table, validated at construction** — the config and the resolver, self-contained, no proxying |
| `02db7e3` | **routing: the pass-through, and the credential rule it enforces** — the proxy, the four properties, 26 tests |
| `eb5ed2b` | **routing: ROUTE_TABLE in the environment, and the contract says where it mounts** — the variable, compose, the document header, the document check |
| `df186df` | **docs: the README tells the truth about routing, and names what is left** — status line, Routing section, configuration table, "Not built yet", AGENTS.md, CHANGELOG |

Committed to `worker/reg-routing-01` only. Not pushed, not merged, not tagged.