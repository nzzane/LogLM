FROM python:3.12-slim

# Build-time proxy (pip). ARG only — never present in the running container.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

WORKDIR /app

# ── Layer 1: pip dependencies (cached until requirements.txt changes) ─────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Layer 2: application package ──────────────────────────────────────────────
# Copy only the app/ sub-directory rather than the whole build context.
#
# Why not 'COPY . .'?
#   COPY . . computes a single cache hash over every file in ./web/.
#   When a new file is added to app/ and that hash hasn't been seen before,
#   Docker *should* rebuild this layer — but if BuildKit's context snapshot
#   was captured before those files existed (common with BuildKit's internal
#   context cache), the snapshot is stale and the new files are invisible.
#
# 'COPY app/ ./app/' fixes this in two ways:
#   1. The cache key covers only app/*.  Any change inside app/ — including
#      adding a new module — immediately invalidates this single layer.
#   2. There is no intermediate 'COPY . .' layer to go stale; the app/
#      directory is always read fresh from the build context on cache miss.
COPY app/ ./app/

# ── Layer 3: purge stale bytecode ─────────────────────────────────────────────
# Remove any __pycache__ / .pyc files that arrived from the build context.
# Stale .pyc files compiled before app/__init__.py existed can cause Python
# to fingerprint 'app' as a namespace package, producing:
#   ImportError: cannot import name 'X' from 'app' (unknown location)
RUN find /app -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true \
 && find /app -name "*.pyc" -delete 2>/dev/null || true

# ── Layer 4: syntax check ──────────────────────────────────────────────────────
# compileall checks every .py file for syntax errors without executing
# module-level code, so it never fails due to missing env vars or DB state.
RUN python -m compileall -q /app/app/ \
 && echo "app/ syntax OK — all modules compiled successfully"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--log-level", "info"]
