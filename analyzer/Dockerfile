FROM python:3.12-slim

# Build-time proxy (pip). ARG only — not present in the running container.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

WORKDIR /app
COPY analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/streams.py ./streams.py
COPY analyzer/ .
CMD ["python", "-u", "main.py"]
