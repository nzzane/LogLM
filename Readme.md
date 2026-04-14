# LogLM Setup Guide

## Quick Start — Mac (M1/M2/M3/M4)

```bash
# 1. Install Ollama on macOS (uses Metal GPU acceleration)
brew install ollama
ollama serve &
ollama pull llama3.2:3b

# 2. Configure
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD, DISCORD_WEBHOOK_URL
# OLLAMA_URL should be: http://host.docker.internal:11434
# OLLAMA_MODEL should be: llama3.2:3b

# 3. Start
docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d

# 4. Open
open http://localhost:8080
```

## Quick Start — Linux with NVIDIA GPU

```bash
# Prerequisites: nvidia-container-toolkit installed
# nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker

cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD, DISCORD_WEBHOOK_URL
# OLLAMA_MODEL: llama3.1:8b-instruct-q4_K_M (fits in 8GB VRAM)

docker compose -f docker-compose.yml -f docker-compose.nvidia.yml up -d

# First boot downloads ~4.7 GB model — watch progress:
docker logs -f loglm-ollama

open http://localhost:8080
```

## Quick Start — External Ollama (any machine)

If you already run Ollama somewhere else on your network:

```bash
cp .env.example .env
# Set OLLAMA_URL=http://YOUR_OLLAMA_IP:11434
# Set OLLAMA_MODEL to whatever you've pulled there

docker compose up -d
open http://localhost:8080
```

## Architecture

```
[Syslog UDP/TCP 514] → syslog-receiver → Redis loglm:raw
[SNMP traps UDP 162]  → snmp service   → Redis loglm:raw
[SNMP polling]        → snmp service   → Redis loglm:raw + loglm:snmp_latest
[LibreNMS API]        → processor      → Redis loglm:raw

Redis loglm:raw → processor (parse + filter) → "keep" / "store" / "drop"
  keep  → Loki + PostgreSQL + Redis loglm:analysis
  store → Loki + PostgreSQL
  drop  → discarded

Redis loglm:analysis → analyzer → Ollama LLM → alerts → Discord + PostgreSQL
analyzer (memory loop) → periodic summaries → PostgreSQL memory_summaries

Web UI → FastAPI → PostgreSQL + Redis + Ollama (chat)
```

## Sending logs to LogLM

### Unifi / UnifiOS
Settings → System → Logging:
- Remote syslog server: `<loglm-host-ip>`
- Port: `514`, Protocol: UDP

### Linux servers (rsyslog)
```bash
echo '*.* @<loglm-host-ip>:514' | sudo tee /etc/rsyslog.d/99-loglm.conf
sudo systemctl restart rsyslog
```

### nginx
```nginx
access_log syslog:server=<loglm-host-ip>:514,facility=local7,tag=nginx combined;
error_log  syslog:server=<loglm-host-ip>:514,facility=local7,tag=nginx_error;
```

### Docker containers
```json
{
  "log-driver": "syslog",
  "log-opts": {
    "syslog-address": "udp://<loglm-host-ip>:514",
    "tag": "{{.Name}}"
  }
}
```

### SNMP polling
Set `SNMP_TARGETS` in `.env`:
```
SNMP_TARGETS=192.168.1.1,192.168.1.2,unifi-ap-living-room
SNMP_COMMUNITY=public
```
Polls interface stats, CPU, wifi clients, errors every `SNMP_POLL_INTERVAL` seconds.

## Chat / Memory System

The **Chat** tab lets you ask the LLM questions about your network in natural language:
- "What happened in the last hour?"
- "Anything look different or unusual?"
- "How are the APs doing?"
- "Summarise today's alerts"

**How memory works:**
- Every 5 minutes (configurable), the analyzer asks the LLM to summarise recent events
- These summaries are stored in PostgreSQL as compressed memory
- When you chat, the last ~30 minutes of summaries + current SNMP metrics + recent alerts + events are loaded as context
- Conversation history is preserved per session

## LLM Model Selection

| Model | VRAM/RAM | Speed | Platform | Notes |
|-------|----------|-------|----------|-------|
| `llama3.2:3b` | ~2 GB | Fast | **Mac recommended** | Great for chat + analysis on Apple Silicon |
| `llama3.1:8b-instruct-q4_K_M` | ~4.7 GB | ~25 tok/s | **NVIDIA recommended** | Best quality under 8 GB |
| `mistral:7b-instruct-q4_K_M` | ~4.1 GB | ~30 tok/s | NVIDIA | Slightly faster, slightly less accurate |
| `llama3.1:8b-instruct-q8_0` | ~8.5 GB | ~15 tok/s | NVIDIA 10+ GB | Higher quality |

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 514  | UDP/TCP  | Syslog ingestion |
| 162  | UDP      | SNMP traps |
| 8080 | TCP      | Web UI (configurable via WEB_PORT) |

## Troubleshooting

```bash
# Check all services
docker compose ps

# Watch processor (filter verdicts)
docker logs -f loglm-processor

# Watch analyzer (LLM calls, alerts, memory summaries)
docker logs -f loglm-analyzer

# Watch SNMP poller
docker logs -f loglm-snmp

# Test syslog
logger -n <loglm-host-ip> -P 514 --udp "test message from $(hostname)"

# Check Redis queue depths
docker exec loglm-redis redis-cli llen loglm:raw
docker exec loglm-redis redis-cli llen loglm:analysis

# Check Ollama is reachable
curl http://localhost:11434/api/tags

# Check memory summaries
docker exec loglm-postgres psql -U loglm loglm \
  -c "SELECT timestamp, LEFT(summary, 100) FROM memory_summaries ORDER BY timestamp DESC LIMIT 5"
```
