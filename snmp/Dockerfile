FROM python:3.12-slim

# Build-time proxy (apt-get + pip). ARG only — not present in the running container.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libsnmp-dev && rm -rf /var/lib/apt/lists/*
COPY snmp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/streams.py ./streams.py
COPY snmp/ .
EXPOSE 162/udp
CMD ["python", "-u", "main.py"]
