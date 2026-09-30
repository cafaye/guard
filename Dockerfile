# syntax=docker/dockerfile:1.7
# guard — the cafaye public gateway. oven/bun slim, multi-stage.
#
#   docker build -t cafaye/guard:dev .
#
# STRICTNESS NOTES (read before loosening anything)
#   - oven/bun:…-slim, never the full image: slim drops the browser and document
#     toolchain a gateway never calls. Bun ships a non-root `bun` user, so the
#     runtime stage uses it instead of creating a second one.
#   - The test stage is a gate, not a report: an image whose suite is red does
#     not build. That is the one place tests run outside CI, and it is why the
#     runtime stage can be a production-only dependency tree.
#   - `bun install --frozen-lockfile` (not plain install): it installs exactly
#     bun.lock and fails when the lock and manifest disagree, which is the point.
#   - No init/tini. Bun is PID 1 via exec form, so SIGTERM reaches the process.
ARG BUN_VERSION=1.3.12

# ---------------------------------------------------------------- deps (all)
FROM oven/bun:${BUN_VERSION}-slim AS deps
WORKDIR /app
ENV CI=true
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# ------------------------------------------------------------------- test
FROM deps AS test
COPY tsconfig.json ./
COPY src ./src
RUN bun test

# -------------------------------------------------------- deps (production)
FROM oven/bun:${BUN_VERSION}-slim AS prod-deps
WORKDIR /app
ENV CI=true
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production && rm -rf /root/.bun/install/cache

# ---------------------------------------------------------------- runtime
FROM oven/bun:${BUN_VERSION}-slim AS runtime
ENV NODE_ENV=production PORT=8080
WORKDIR /app

COPY --from=prod-deps --chown=bun:bun /app/node_modules ./node_modules
COPY --chown=bun:bun package.json ./
COPY --chown=bun:bun src ./src

USER bun
EXPOSE 8080
CMD ["bun", "run", "src/index.ts"]
