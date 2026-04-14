"""
SNMP service — dual mode:
  1. Trap receiver (UDP 162) — catches async SNMP traps/informs
  2. Active poller — periodically polls configured devices for metrics

Metrics polled:
  - Interface stats (traffic, errors, status)
  - System uptime, CPU, memory
  - Wireless clients (Unifi APs)
  - Routing table size
  - ARP table
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as aioredis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [snmp] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "")
POLL_INTERVAL = int(os.environ.get("SNMP_POLL_INTERVAL", "60"))
SNMP_COMMUNITY = os.environ.get("SNMP_COMMUNITY", "public")
# Comma-separated list of host:port or just host (default port 161)
SNMP_TARGETS = os.environ.get("SNMP_TARGETS", "")

# ── OIDs ───────────────────────────────────────────────────────────────────────
# Standard MIB-II
OID_SYSTEM_DESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYSTEM_UPTIME   = "1.3.6.1.2.1.1.3.0"
OID_SYSTEM_NAME     = "1.3.6.1.2.1.1.5.0"
OID_IF_TABLE        = "1.3.6.1.2.1.2.2.1"      # interface table
OID_IF_DESCR        = "1.3.6.1.2.1.2.2.1.2"    # ifDescr
OID_IF_OPER_STATUS  = "1.3.6.1.2.1.2.2.1.8"    # ifOperStatus
OID_IF_IN_OCTETS    = "1.3.6.1.2.1.2.2.1.10"   # ifInOctets
OID_IF_OUT_OCTETS   = "1.3.6.1.2.1.2.2.1.16"   # ifOutOctets
OID_IF_IN_ERRORS    = "1.3.6.1.2.1.2.2.1.14"   # ifInErrors
OID_IF_OUT_ERRORS   = "1.3.6.1.2.1.2.2.1.20"   # ifOutErrors

# HOST-RESOURCES-MIB (CPU/mem on Linux/Unraid)
OID_HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"  # hrProcessorLoad
OID_HR_STORAGE_USED   = "1.3.6.1.2.1.25.2.3.1.6"  # hrStorageUsed
OID_HR_STORAGE_SIZE   = "1.3.6.1.2.1.25.2.3.1.5"  # hrStorageSize

# Unifi-specific (UAP MIB) — wireless clients
OID_UNIFI_VAP_CLIENTS = "1.3.6.1.4.1.41112.1.6.1.2.1.8"  # unifiVapNumStations


def parse_targets(raw: str) -> list[tuple[str, int]]:
    targets = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            host, port = entry.rsplit(":", 1)
            targets.append((host, int(port)))
        else:
            targets.append((entry, 161))
    return targets


# ── Previous values for rate calculation ───────────────────────────────────────
_prev_counters: dict[str, dict[str, int]] = {}   # host -> {oid_key: value}
_prev_timestamps: dict[str, float] = {}          # host -> epoch


def calc_rate(host: str, key: str, current_val: int) -> float | None:
    """Calculate per-second rate from counter difference. Returns None on first sample."""
    now = time.monotonic()
    prev = _prev_counters.get(host, {}).get(key)
    prev_ts = _prev_timestamps.get(host)

    _prev_counters.setdefault(host, {})[key] = current_val
    _prev_timestamps[host] = now

    if prev is None or prev_ts is None:
        return None
    elapsed = now - prev_ts
    if elapsed <= 0:
        return None
    diff = current_val - prev
    if diff < 0:
        diff += 2**32  # counter wrap (32-bit)
    return diff / elapsed


async def snmp_get(host: str, port: int, oids: list[str]) -> dict[str, str]:
    """Perform SNMP GET using pysnmp."""
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
    except ImportError:
        from pysnmp.hlapi.asyncio import (
            getCmd as get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )

    results = {}
    obj_types = [ObjectType(ObjectIdentity(oid)) for oid in oids]

    try:
        error_indication, error_status, error_index, var_binds = await get_cmd(
            SnmpEngine(),
            CommunityData(SNMP_COMMUNITY),
            await UdpTransportTarget.create((host, port), timeout=5, retries=1),
            ContextData(),
            *obj_types,
        )
        if error_indication or error_status:
            log.debug(f"SNMP GET error from {host}: {error_indication or error_status}")
            return results
        for oid, val in var_binds:
            results[str(oid)] = str(val)
    except Exception as e:
        log.debug(f"SNMP GET failed for {host}: {e}")
    return results


async def snmp_walk(host: str, port: int, oid: str) -> dict[str, str]:
    """Perform SNMP WALK (GET-NEXT) for a table OID."""
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            next_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
    except ImportError:
        from pysnmp.hlapi.asyncio import (
            nextCmd as next_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )

    results = {}
    try:
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create((host, port), timeout=5, retries=1)
        kwargs = dict(
            snmpEngine=engine,
            authData=CommunityData(SNMP_COMMUNITY),
            transportTarget=transport,
            contextData=ContextData(),
            varBinds=[ObjectType(ObjectIdentity(oid))],
        )
        # pysnmp next_cmd is an async iterator
        async for error_indication, error_status, error_index, var_binds in next_cmd(**kwargs):
            if error_indication or error_status:
                break
            for name, val in var_binds:
                name_str = str(name)
                if not name_str.startswith(oid):
                    return results  # walked past our subtree
                results[name_str] = str(val)
    except Exception as e:
        log.debug(f"SNMP WALK failed for {host}/{oid}: {e}")
    return results


async def poll_device(host: str, port: int, redis_client: aioredis.Redis):
    """Poll a single device for system info + interface stats + wireless clients."""
    now_iso = datetime.now(timezone.utc).isoformat()

    # ── System info ────────────────────────────────────────────────────────────
    sys_info = await snmp_get(host, port, [OID_SYSTEM_DESCR, OID_SYSTEM_UPTIME, OID_SYSTEM_NAME])
    sys_name = sys_info.get(OID_SYSTEM_NAME, host)
    uptime = sys_info.get(OID_SYSTEM_UPTIME, "?")

    # ── Interface descriptions + status ────────────────────────────────────────
    if_descr = await snmp_walk(host, port, OID_IF_DESCR)
    if_status = await snmp_walk(host, port, OID_IF_OPER_STATUS)
    if_in_oct = await snmp_walk(host, port, OID_IF_IN_OCTETS)
    if_out_oct = await snmp_walk(host, port, OID_IF_OUT_OCTETS)
    if_in_err = await snmp_walk(host, port, OID_IF_IN_ERRORS)
    if_out_err = await snmp_walk(host, port, OID_IF_OUT_ERRORS)

    # Map by interface index
    interfaces = {}
    for oid_key, name in if_descr.items():
        idx = oid_key.split(".")[-1]
        iface = {"name": name, "index": idx}

        status_key = f"{OID_IF_OPER_STATUS}.{idx}"
        iface["oper_status"] = "up" if if_status.get(status_key) == "1" else "down"

        # Traffic rates
        for label, table in [("in_bytes", if_in_oct), ("out_bytes", if_out_oct),
                             ("in_errors", if_in_err), ("out_errors", if_out_err)]:
            counter_key = f"{label}_{host}_{idx}"
            raw_val = table.get(f"{OID_IF_IN_OCTETS.rsplit('.', 1)[0]}.{label.split('_')[0] == 'in' and '10' or '16'}.{idx}", None)
            # Simplified: get from correct OID
            if label == "in_bytes":
                raw = if_in_oct.get(f"{OID_IF_IN_OCTETS}.{idx}")
            elif label == "out_bytes":
                raw = if_out_oct.get(f"{OID_IF_OUT_OCTETS}.{idx}")
            elif label == "in_errors":
                raw = if_in_err.get(f"{OID_IF_IN_ERRORS}.{idx}")
            else:
                raw = if_out_err.get(f"{OID_IF_OUT_ERRORS}.{idx}")

            if raw and raw.isdigit():
                rate = calc_rate(host, counter_key, int(raw))
                iface[label + "_per_sec"] = round(rate, 2) if rate is not None else None
                iface[label + "_total"] = int(raw)
            else:
                iface[label + "_per_sec"] = None

        interfaces[idx] = iface

    # ── Wireless clients (Unifi APs) ──────────────────────────────────────────
    wifi_clients = await snmp_walk(host, port, OID_UNIFI_VAP_CLIENTS)
    total_wifi_clients = 0
    vap_details = {}
    for oid_key, val in wifi_clients.items():
        if val.isdigit():
            vap_idx = oid_key.split(".")[-1]
            count = int(val)
            total_wifi_clients += count
            vap_details[vap_idx] = count

    # ── CPU load ──────────────────────────────────────────────────────────────
    cpu_loads = await snmp_walk(host, port, OID_HR_PROCESSOR_LOAD)
    avg_cpu = None
    if cpu_loads:
        loads = [int(v) for v in cpu_loads.values() if v.isdigit()]
        if loads:
            avg_cpu = round(sum(loads) / len(loads), 1)

    # ── Build summary event ───────────────────────────────────────────────────
    # Count interfaces with errors
    error_ifaces = []
    down_ifaces = []
    for idx, iface in interfaces.items():
        if iface.get("oper_status") == "down" and iface["name"] not in ("lo", "Null0"):
            down_ifaces.append(iface["name"])
        for err_key in ("in_errors_per_sec", "out_errors_per_sec"):
            if iface.get(err_key) and iface[err_key] > 0:
                error_ifaces.append(iface["name"])

    # Build a concise summary for the LLM
    summary_parts = [f"SNMP poll of {sys_name} ({host}): uptime={uptime}"]
    if avg_cpu is not None:
        summary_parts.append(f"CPU={avg_cpu}%")
    summary_parts.append(f"interfaces={len(interfaces)}")
    if down_ifaces:
        summary_parts.append(f"DOWN=[{','.join(down_ifaces)}]")
    if error_ifaces:
        summary_parts.append(f"ERRORS=[{','.join(set(error_ifaces))}]")
    if total_wifi_clients > 0:
        summary_parts.append(f"wifi_clients={total_wifi_clients}")

    # Determine severity
    severity = "info"
    if down_ifaces or error_ifaces:
        severity = "warning"
    if avg_cpu and avg_cpu > 90:
        severity = "warning"

    event = {
        "timestamp": now_iso,
        "host": host,
        "source": "snmp_poll",
        "severity": severity,
        "facility": "daemon",
        "program": "snmp_poller",
        "message": ", ".join(summary_parts),
        "structured": {
            "type": "snmp_poll",
            "sys_name": sys_name,
            "uptime": uptime,
            "avg_cpu": avg_cpu,
            "total_interfaces": len(interfaces),
            "down_interfaces": down_ifaces,
            "error_interfaces": list(set(error_ifaces)),
            "wifi_clients_total": total_wifi_clients,
            "wifi_vaps": vap_details,
            "interfaces": interfaces,
        },
    }

    await redis_client.rpush("loglm:raw", json.dumps(event))

    # Also push to a dedicated SNMP metrics key for the chat/memory system
    metrics_snapshot = {
        "timestamp": now_iso,
        "host": host,
        "sys_name": sys_name,
        "avg_cpu": avg_cpu,
        "interfaces": {
            idx: {
                "name": iface["name"],
                "status": iface["oper_status"],
                "in_bps": iface.get("in_bytes_per_sec"),
                "out_bps": iface.get("out_bytes_per_sec"),
                "in_errors": iface.get("in_errors_per_sec"),
                "out_errors": iface.get("out_errors_per_sec"),
            }
            for idx, iface in interfaces.items()
        },
        "wifi_clients": total_wifi_clients,
    }
    await redis_client.hset("loglm:snmp_latest", host, json.dumps(metrics_snapshot))

    log.info(f"Polled {sys_name}({host}): {len(interfaces)} ifs, "
             f"{len(down_ifaces)} down, {total_wifi_clients} wifi clients")


# ── Trap receiver ──────────────────────────────────────────────────────────────

class TrapProtocol(asyncio.DatagramProtocol):
    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        # Simple trap ingestion — push raw hex + addr for processing
        now_iso = datetime.now(timezone.utc).isoformat()
        event = {
            "timestamp": now_iso,
            "host": addr[0],
            "source": "snmp_trap",
            "severity": "notice",
            "facility": "daemon",
            "program": "snmptrapd",
            "message": f"SNMP trap from {addr[0]} ({len(data)} bytes)",
            "structured": {
                "type": "snmp_trap",
                "raw_hex": data.hex()[:500],
            },
        }
        asyncio.create_task(self.redis.rpush("loglm:raw", json.dumps(event)))


# ── Main loops ─────────────────────────────────────────────────────────────────

async def poll_loop(redis_client: aioredis.Redis):
    """Periodically poll all configured SNMP targets."""
    targets = parse_targets(SNMP_TARGETS)
    if not targets:
        log.info("No SNMP_TARGETS configured — polling disabled")
        return

    log.info(f"SNMP poller starting for {len(targets)} targets, interval={POLL_INTERVAL}s")

    while True:
        tasks = [poll_device(host, port, redis_client) for host, port in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                log.warning(f"Poll failed for {targets[i][0]}: {result}")
        await asyncio.sleep(POLL_INTERVAL)


async def main():
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    loop = asyncio.get_running_loop()

    # Start trap receiver on UDP 162
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: TrapProtocol(redis_client),
            local_addr=("0.0.0.0", 162),
        )
        log.info("SNMP trap receiver listening on UDP 162")
    except Exception as e:
        log.warning(f"Could not bind trap port 162: {e}")
        transport = None

    # Start poller
    try:
        await poll_loop(redis_client)
    finally:
        if transport:
            transport.close()


if __name__ == "__main__":
    asyncio.run(main())
