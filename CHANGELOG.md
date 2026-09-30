# Changelog

All notable changes to `guard` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). `core`'s
mini-semver grammar (`^`, `~`, `>=`, exact) is what `cafaye.yml` uses; npm
dependency versions follow npm's own rules.

## [Unreleased]

### Added

- App factory `createApp`, exported for tests and the only import the suite
  makes. Importing the module never opens a socket; the `Bun.serve` bootstrap
  is behind `import.meta.main`.
- `GET /healthz` — unconditional `200 {"status":"ok"}`. Liveness never touches a
  dependency.
- `GET /readyz` — `200 {"deps":{…}}`, or `503` naming the dependencies that are
  not ok. A probe that throws, rejects or answers with anything but `"ok"` counts
  as `unavailable`; v0 registers no probes, so it is unconditionally ready.
- `requireJwt` middleware — **stub**. 401 when the `Authorization` header is
  absent or empty, pass-through otherwise. No token is parsed or verified.
- `rateLimit` middleware — in-memory fixed-window limiter with wall-clock
  aligned windows, `X-RateLimit-Limit` / `-Remaining` / `-Reset` on allowed and
  rejected requests alike, and `Retry-After` on a 429. Invalid `limit` or
  `windowMs` throws at construction.
- JSON `404` for unknown routes and a flat JSON `500` for unhandled handler
  errors, with the detail logged rather than returned.
- Rate limiting skips both probe endpoints.
- `Dockerfile` (oven/bun slim, multi-stage, tests gate the image),
  `docker-compose.yml` (the service only), `bin/prime`, `mise.toml`, `AGENTS.md`
  and this changelog.
- `cafaye.yml` against `core`'s frozen manifest schema, with a
  `DECISION NEEDED` for the `exposes` block that needs a manager-owned OpenAPI
  document.

[Unreleased]: https://github.com/cafaye/guard/compare/v0.0.0...HEAD
[v0.0.0]: https://github.com/cafaye/guard/releases/tag/v0.0.0
