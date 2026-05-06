#!/usr/bin/env bash
# sync_to_server.sh
# Usage: bash scripts/sync_to_server.sh [user@host] [remote_path]
#
# Copies every file that exists on the dev machine but is absent from the
# Unraid server.  Run from the project root on the Windows machine via WSL,
# Git Bash, or any ssh-capable terminal.
#
# Default target mirrors the path seen in the build logs:
#   root@Minerva:/mnt/user/appdata/LogLM
#
# Override with arguments, e.g.:
#   bash scripts/sync_to_server.sh admin@192.168.1.50 /srv/loglm

TARGET_HOST="${1:-root@Minerva}"
TARGET_PATH="${2:-/mnt/user/appdata/LogLM}"

set -euo pipefail

echo "==> Syncing missing files to ${TARGET_HOST}:${TARGET_PATH}"

# ── Python modules (new, never existed on server) ────────────────────────────
scp web/app/__init__.py    "${TARGET_HOST}:${TARGET_PATH}/web/app/__init__.py"
scp web/app/opscenter.py   "${TARGET_HOST}:${TARGET_PATH}/web/app/opscenter.py"
scp web/app/hitl.py        "${TARGET_HOST}:${TARGET_PATH}/web/app/hitl.py"
scp web/app/correlation.py "${TARGET_HOST}:${TARGET_PATH}/web/app/correlation.py"
scp web/app/log_tiers.py   "${TARGET_HOST}:${TARGET_PATH}/web/app/log_tiers.py"

# ── Templates (new pages) ─────────────────────────────────────────────────────
scp web/app/templates/audit_log.html  "${TARGET_HOST}:${TARGET_PATH}/web/app/templates/audit_log.html"
scp web/app/templates/hitl.html       "${TARGET_HOST}:${TARGET_PATH}/web/app/templates/hitl.html"
scp web/app/templates/opscenter.html  "${TARGET_HOST}:${TARGET_PATH}/web/app/templates/opscenter.html"
scp web/app/templates/users.html      "${TARGET_HOST}:${TARGET_PATH}/web/app/templates/users.html"

# ── Config files changed in this session ─────────────────────────────────────
scp web/Dockerfile         "${TARGET_HOST}:${TARGET_PATH}/web/Dockerfile"
scp web/requirements.txt   "${TARGET_HOST}:${TARGET_PATH}/web/requirements.txt"
scp web/app/main.py        "${TARGET_HOST}:${TARGET_PATH}/web/app/main.py"
scp web/app/auth.py        "${TARGET_HOST}:${TARGET_PATH}/web/app/auth.py"
scp web/app/templates/alerts.html   "${TARGET_HOST}:${TARGET_PATH}/web/app/templates/alerts.html"
scp web/app/templates/base.html     "${TARGET_HOST}:${TARGET_PATH}/web/app/templates/base.html"
scp web/app/templates/settings.html "${TARGET_HOST}:${TARGET_PATH}/web/app/templates/settings.html"
scp web/app/templates/topology.html "${TARGET_HOST}:${TARGET_PATH}/web/app/templates/topology.html"
scp docker-compose.yml     "${TARGET_HOST}:${TARGET_PATH}/docker-compose.yml"
scp .env.example           "${TARGET_HOST}:${TARGET_PATH}/.env.example"
scp postgres/init.sql      "${TARGET_HOST}:${TARGET_PATH}/postgres/init.sql"
scp analyzer/main.py       "${TARGET_HOST}:${TARGET_PATH}/analyzer/main.py"
scp analyzer/tier3.py      "${TARGET_HOST}:${TARGET_PATH}/analyzer/tier3.py"
scp processor/fast_categorizer.py "${TARGET_HOST}:${TARGET_PATH}/processor/fast_categorizer.py"

echo ""
echo "==> Verifying files arrived on server..."
ssh "${TARGET_HOST}" "ls -lh ${TARGET_PATH}/web/app/*.py ${TARGET_PATH}/web/app/templates/*.html"

echo ""
echo "==> All done. Rebuild with:"
echo "    ssh ${TARGET_HOST} 'cd ${TARGET_PATH} && docker compose up --build --force-recreate web'"
