# CLAUDE.md

Conventions for working in this repository live in [AGENTS.md](./AGENTS.md) —
read that instead. This file is a pointer, kept so tooling that looks for
`CLAUDE.md` finds one source of truth rather than a second, drifting copy.

The short version: Bun, not Node (`bun test`, `bun install`, `bunx`); tests
first; `createApp` is the only import the tests make.
