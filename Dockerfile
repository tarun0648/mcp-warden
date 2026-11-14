# syntax=docker/dockerfile:1.7
#
# mcp-warden gateway image.
#
#   docker build -t mcp-warden .                       # rules-only, ~small
#   docker build -t mcp-warden:ml --build-arg WITH_ML=true .   # plus the local classifier
#
# Two stages: `build` resolves the locked dependencies with uv; `runtime` gets only the
# virtualenv, the source and the config, runs as an unprivileged user, and is designed for a
# read-only root filesystem (see docker-compose.yml: `read_only: true`). Everything the
# gateway writes goes under /var/lib/warden, which compose mounts as volumes.
#
# Base images are pinned by digest as well as tag: a tag can be re-pushed, a digest cannot.

ARG PYTHON_IMAGE=python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.0@sha256:606e70c71c852d03f611b1e56a195d08648507018a7057fab82c4974c4eae105

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS build

ARG WITH_ML=false
COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Dependencies first, from the lockfile only, so a source change does not re-resolve them.
# `--frozen` fails the build if uv.lock and pyproject.toml disagree rather than quietly
# resolving something nobody reviewed.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    set -eu; \
    extra=""; if [ "$WITH_ML" = "true" ]; then extra="--extra ml"; fi; \
    uv sync --frozen --no-dev --no-install-project $extra

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    set -eu; \
    extra=""; if [ "$WITH_ML" = "true" ]; then extra="--extra ml"; fi; \
    uv sync --frozen --no-dev $extra

# ---------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ARG WITH_ML=false
LABEL org.opencontainers.image.title="mcp-warden" \
      org.opencontainers.image.description="A security gateway for the Model Context Protocol" \
      org.opencontainers.image.licenses="MIT" \
      io.mcp-warden.with-ml="${WITH_ML}"

# A fixed, unprivileged uid/gid with no login shell. Fixed so volume ownership is predictable.
RUN groupadd --system --gid 10001 warden \
 && useradd --system --uid 10001 --gid warden --home-dir /var/lib/warden \
            --shell /usr/sbin/nologin warden \
 && mkdir -p /var/lib/warden/data /var/lib/warden/sandbox /var/lib/warden/keys /var/lib/warden/hf \
 && chown -R warden:warden /var/lib/warden \
 && chmod 0700 /var/lib/warden/keys

# uv stays in the runtime image because servers.yaml launches the stdio upstreams with
# `uv run`, the same command as on a laptop. UV_NO_SYNC makes it a launcher only: it never
# resolves or installs anything at runtime, and with a read-only root it could not.
COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/src /app/src
COPY pyproject.toml uv.lock alembic.ini README.md ./
COPY migrations ./migrations
COPY servers ./servers
COPY config ./config
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_NO_SYNC=1 \
    UV_FROZEN=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_PYTHON_DOWNLOADS=never \
    HOME=/var/lib/warden \
    HF_HOME=/var/lib/warden/hf \
    WARDEN_HOST=0.0.0.0 \
    WARDEN_PORT=8080 \
    CONFIG_DIR=/app/config \
    JWT_KEY_DIR=/var/lib/warden/keys \
    NOTES_DB_PATH=/var/lib/warden/data/notes.sqlite3 \
    FILES_SANDBOX_ROOT=/var/lib/warden/sandbox

USER warden:warden
EXPOSE 8080

# Liveness only: /healthz answers whenever the process can serve. Readiness (/readyz) needs
# Postgres and Redis, which is the orchestrator's business, not the container's.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
