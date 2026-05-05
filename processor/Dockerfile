FROM python:3.12-slim

# Build-time proxy (pip). ARG only — not present in the running container.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

WORKDIR /app
COPY processor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/streams.py ./streams.py
COPY shared/geoip.py ./geoip.py
COPY processor/ .
CMD ["python", "-u", "main.py"]
