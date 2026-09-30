#!/usr/bin/env bash
#
# kit template — prime a Bun worktree. Copy to bin/prime in the service repo and
# run it after `git clone`, `git worktree add`, or `git pull --rebase`.
#
#   bin/prime            # frozen install, typecheck, then the full test suite
#   bin/prime --fast     # frozen install only
#
# WHAT IT PROMISES
#   Exit 0: bun.lock installs exactly, the type checker is clean, and every test
#   passes. Anything else: nonzero, with the failing step named.
#   `set -euo pipefail` is the whole mechanism — no error handling to forget.
#
# STRICTNESS NOTES
#   - No `mise install` here. mise.toml pins bun; this script only primes
#     dependencies and fails loudly (127) if the toolchain is missing.
#   - `bun install --frozen-lockfile` (never plain `bun install`): frozen installs
#     exactly bun.lock and FAILS when the lock and package.json disagree. Plain
#     `bun install` would quietly rewrite the lock, which is how a lockfile
#     reaches master having drifted from the manifest it claims to describe.
#   - `typecheck` before `test`, and `tsc --noEmit` inside it. A Bun service
#     type-checks rather than transpiles, so a type error that the test run
#     tolerates would otherwise ship.
#   - `bun test`, the runner the repo's own `package.json` names. Not `bunx jest`:
#     a prime that runs something other than what CI runs proves nothing about CI.
#
# This is the sibling of bin-prime/node.sh, not a copy of it. Two differences are
# load-bearing and are the reason this file exists rather than a symlink: bun
# ships its own test runner, and bun's lockfile is bun.lock.

set -euo pipefail

FAST=0
for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    -h | --help)
      sed -n '2,22p' "$0"
      exit 0
      ;;
    *)
      echo "bin/prime: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "bin/prime: $1 not found on PATH — run 'mise install' in this worktree" >&2
    exit 127
  fi
}

step() {
  printf '\n== %s\n' "$1"
}

# Never fails the prime. The toolchain check below is the gate; a banner must not
# be able to turn a green prime red.
version_of() {
  "$@" --version 2>/dev/null | head -n 1 || true
}

require bun

step "bun install --frozen-lockfile"
bun install --frozen-lockfile

if [ "$FAST" -eq 1 ]; then
  step "skipping typecheck and tests (--fast)"
  exit 0
fi

# Probed rather than assumed: a repo with no typecheck script yet is a day-one
# repo, not a broken one. A repo that HAS the script must pass it.
if bun -e 'process.exit(require("./package.json").scripts?.typecheck ? 0 : 1)' \
  >/dev/null 2>&1; then
  step "bun run typecheck"
  bun run typecheck
else
  echo "bin/prime: no 'typecheck' script in package.json — skipping typecheck" >&2
fi

step "bun test"
bun test

version="$(version_of bun)"
step "prime ok (bun ${version:-unknown})"
