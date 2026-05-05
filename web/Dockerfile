FROM python:3.12-slim

# Build-time proxy (pip). ARG only — not present in the running container.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

WORKDIR /app

# ── Layer 1: dependencies (cached until requirements.txt changes) ────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Layer 2: bulk source copy ────────────────────────────────────────────────
COPY . .

# ── Layer 3: guarantee critical files added after the base build exist ────────
# Docker's layer cache key for COPY . . is the combined hash of the build
# context. If the cache pre-dates the creation of the files below, those files
# will be absent from the cached layer — causing Python to treat 'app' as a
# namespace package and report:
#   ImportError: cannot import name 'X' from 'app' (unknown location)
#
# Each explicit COPY below has its OWN content-hash cache entry.  Docker only
# re-runs it when that specific source file changes, but it always runs if its
# cache entry is newer than the COPY . . layer — which is exactly what we want.
COPY app/__init__.py    ./app/__init__.py
COPY app/opscenter.py   ./app/opscenter.py
COPY app/hitl.py        ./app/hitl.py
COPY app/correlation.py ./app/correlation.py
COPY app/log_tiers.py   ./app/log_tiers.py

# ── Layer 4: purge stale bytecode ────────────────────────────────────────────
# Remove any __pycache__ directories / .pyc files that came from the build
# context or were created by previous pip-install subprocesses.  Stale .pyc
# files can hold a namespace-package fingerprint for 'app' compiled before
# __init__.py existed, causing the same (unknown location) error at runtime.
RUN find /app -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true \
 && find /app -name "*.pyc" -delete 2>/dev/null || true

# ── Layer 5: syntax check ─────────────────────────────────────────────────────
# compileall compiles every .py in app/ to bytecode, catching syntax errors at
# build time.  Unlike 'import app.main', it does NOT execute module-level code,
# so it never fails due to missing env vars, DB connections, or asyncio state.
RUN python -m compileall -q /app/app/ \
 && echo "app/ syntax OK — all modules compiled successfully"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--log-level", "info"]
