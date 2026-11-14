#!/bin/sh
# Container entrypoint: bring the database schema and signing key up to date, then run the
# gateway. Both steps are idempotent, so a restart is always safe.
#
# Only `serve` triggers them; any other command (`warden tools list`, `warden keys create`,
# ...) runs as given, so `docker compose exec gateway warden ...` works for operators.
set -eu

if [ "${1:-serve}" = "serve" ]; then
    warden db upgrade
    warden keys init-jwt
fi

exec warden "$@"
