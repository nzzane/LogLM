FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer-cached until requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source.
# Explicitly delete any __pycache__ directories from the build context so
# stale .pyc files from a developer's local Python never bleed into the image.
# This prevents the "ImportError: cannot import name X from 'app' (unknown
# location)" failure caused by cached namespace-package metadata from a prior
# build that pre-dated the addition of app/__init__.py.
COPY . .
RUN find /app -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true \
 && find /app -name "*.pyc" -delete 2>/dev/null || true

# Pre-compile to catch import errors at build time rather than at container startup
RUN python -c "import app.main; print('package import OK')"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--log-level", "info"]
