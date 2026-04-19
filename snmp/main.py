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

import streams

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

# IF-MIB Extended (64-bit HC counters — more accurate for >1Gbps)
OID_IFX_TABLE           = "1.3.6.1.2.1.31.1.1.1"
OID_IFX_IN_HC_OCTETS    = "1.3.6.1.2.1.31.1.1.1.6"   # ifHCInOctets
OID_IFX_OUT_HC_OCTETS   = "1.3.6.1.2.1.31.1.1.1.10"  # ifHCOutOctets
OID_IFX_ALIAS           = "1.3.6.1.2.1.31.1.1.1.18"  # ifAlias (admin description)
OID_IFX_SPEED_HIGH      = "1.3.6.1.2.1.31.1.1.1.15"  # ifHighSpeed (Mbps)

# ENTITY-SENSOR-MIB (RFC 3433) — physical sensor readings incl. SFP transceivers
OID_ENT_SENSOR_TYPE     = "1.3.6.1.2.1.99.1.1.1.1"   # entPhySensorType
OID_ENT_SENSOR_SCALE    = "1.3.6.1.2.1.99.1.1.1.2"   # entPhySensorScale (UOM power of 10)
OID_ENT_SENSOR_PREC     = "1.3.6.1.2.1.99.1.1.1.3"   # entPhySensorPrecision
OID_ENT_SENSOR_VALUE    = "1.3.6.1.2.1.99.1.1.1.4"   # entPhySensorValue
OID_ENT_SENSOR_UNITS    = "1.3.6.1.2.1.99.1.1.1.5"   # entPhySensorUnitsDisplay

# ENTITY-MIB — physical component names (to label sensor readings)
OID_ENT_PHYS_NAME       = "1.3.6.1.2.1.47.1.1.1.1.7"  # entPhysicalName
OID_ENT_PHYS_DESCR      = "1.3.6.1.2.1.47.1.1.1.1.2"  # entPhysicalDescr

# Sensor type enum values from ENTITY-SENSOR-MIB
_SENSOR_TYPE_CELSIUS = 8
_SENSOR_TYPE_DBM     = 14

# ENTITY-SENSOR-MIB SensorDataScale enum → power-of-10 exponent
_SCALE_EXPONENTS: dict[int, int] = {
    1: -24, 2: -21, 3: -18, 4: -15, 5: -12, 6: -9,
    7: -6,  8: -3,  9: 0,   10: 3,  11: 6,  12: 9,
    13: 12, 14: 15, 15: 18, 16: 21, 17: 24,
}

def _apply_sensor_scale(raw: int, scale: int, precision: int) -> float:
    """Convert ENTITY-SENSOR-MIB raw integer → real-world float.
    actual = raw × 10^(scale_exponent − precision)
    e.g. raw=235, scale=9 (units), precision=1 → 23.5°C
    """
    exp = _SCALE_EXPONENTS.get(scale, 0) - precision
    return raw * (10.0 ** exp)

# IP-MIB — ARP / neighbour table for topology inference
OID_IP_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"  # ipNetToMediaPhysAddress (MAC)
OID_IP_NET_TO_MEDIA_ADDR = "1.3.6.1.2.1.4.22.1.3"  # ipNetToMediaNetAddress  (IP, redundant but easier)
OID_IP_NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"  # ipNetToMediaType (3=dynamic, 4=static)

# LLDP-MIB — neighbour discovery for auto-topology
OID_LLDP_REM_TABLE      = "1.0.8802.1.1.2.1.4.1.1"
OID_LLDP_REM_SYS_NAME   = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_PORT_ID    = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_PORT_DESC  = "1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_REM_MGMT_ADDR  = "1.0.8802.1.1.2.1.4.2.1.4"
OID_LLDP_LOC_PORT_DESC  = "1.0.8802.1.1.2.1.3.7.1.4"

LLDP_POLL_INTERVAL = int(os.environ.get("LLDP_POLL_INTERVAL", "300"))


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


# ── Schema migration + DB-backed device list ───────────────────────────────────

async def ensure_device_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS snmp_devices (
                id          SERIAL PRIMARY KEY,
                host        TEXT NOT NULL UNIQUE,
                port        INT  NOT NULL DEFAULT 161,
                community   TEXT NOT NULL DEFAULT 'public',
                device_type TEXT NOT NULL DEFAULT 'auto',
                label       TEXT,
                enabled     BOOLEAN NOT NULL DEFAULT TRUE,
                source      TEXT NOT NULL DEFAULT 'manual',
                last_polled TIMESTAMPTZ,
                last_status TEXT,
                last_error  TEXT,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                updated_at  TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_snmp_devices_enabled ON snmp_devices (enabled);
        """)


async def bootstrap_env_targets(pool: asyncpg.Pool) -> None:
    """Seed snmp_devices from SNMP_TARGETS env on first startup so the env-var
    workflow keeps working. Existing rows are left untouched."""
    if not SNMP_TARGETS:
        return
    targets = parse_targets(SNMP_TARGETS)
    async with pool.acquire() as conn:
        for host, port in targets:
            await conn.execute(
                """INSERT INTO snmp_devices (host, port, community, source)
                   VALUES ($1, $2, $3, 'env')
                   ON CONFLICT (host) DO NOTHING""",
                host, port, SNMP_COMMUNITY,
            )


async def load_devices(pool: asyncpg.Pool) -> list[dict]:
    if pool is None:
        return []
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, host, port, community, device_type, label "
            "FROM snmp_devices WHERE enabled = TRUE"
        )
    return [dict(r) for r in rows]


async def update_device_status(pool: asyncpg.Pool, host: str,
                                status: str, error: str | None = None) -> None:
    if pool is None:
        return
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE snmp_devices SET last_polled=NOW(), last_status=$1, "
                "last_error=$2, updated_at=NOW() WHERE host=$3",
                status, error, host,
            )
    except Exception as e:
        log.debug(f"snmp_devices status update failed for {host}: {e}")


# ── Previous values for rate calculation ───────────────────────────────────────
_prev_counters: dict[str, dict[str, int]] = {}   # host -> {oid_key: value}
_prev_timestamps: dict[str, float] = {}          # host -> epoch


def calc_rate(host: str, key: str, current_val: int, bits: int = 32) -> float | None:
    """Calculate per-second rate from counter difference. Returns None on first sample.
    bits: counter width for wrap detection (32 for MIB-II, 64 for HC counters)."""
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
        diff += 2 ** bits  # counter wrap
    return diff / elapsed


async def snmp_get(host: str, port: int, oids: list[str],
                    community: str = SNMP_COMMUNITY) -> dict[str, str]:
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
            CommunityData(community),
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


async def snmp_walk(host: str, port: int, oid: str,
                     community: str = SNMP_COMMUNITY) -> dict[str, str]:
    """SNMP WALK that actually walks. pysnmp 7's `next_cmd` is single-shot —
    use `bulk_walk_cmd` (auto-walking async generator). Falls back to
    `walk_cmd`, then a manual `next_cmd` loop for older builds."""
    bulk = walk = next_cmd = None
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
        try:
            from pysnmp.hlapi.v3arch.asyncio import bulk_walk_cmd as bulk
        except ImportError:
            pass
        try:
            from pysnmp.hlapi.v3arch.asyncio import walk_cmd as walk
        except ImportError:
            pass
        if bulk is None and walk is None:
            from pysnmp.hlapi.v3arch.asyncio import next_cmd  # noqa: F401
    except ImportError:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            nextCmd as next_cmd, SnmpEngine, CommunityData,
            UdpTransportTarget, ContextData, ObjectType, ObjectIdentity,
        )

    results: dict[str, str] = {}
    base = oid.lstrip(".")
    try:
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create((host, port), timeout=5, retries=1)
        var = ObjectType(ObjectIdentity(oid))

        if bulk is not None:
            # mpModel=1 → SNMPv2c (required for GETBULK)
            iterator = bulk(
                engine, CommunityData(community, mpModel=1), transport,
                ContextData(), 0, 25, var,
            )
        elif walk is not None:
            iterator = walk(
                engine, CommunityData(community), transport,
                ContextData(), var,
            )
        else:
            iterator = None

        if iterator is not None:
            async for err_ind, err_stat, _err_idx, var_binds in iterator:
                if err_ind or err_stat:
                    break
                stop = False
                for name, val in var_binds:
                    name_str = str(name).lstrip(".")
                    if not name_str.startswith(base):
                        stop = True
                        break
                    results[name_str] = (
                        val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
                    )
                if stop:
                    break
        else:
            # Manual GETNEXT loop (older pysnmp / final fallback)
            current = var
            for _ in range(2000):
                err_ind, err_stat, _err_idx, var_binds = await next_cmd(
                    engine, CommunityData(community), transport,
                    ContextData(), current,
                )
                if err_ind or err_stat or not var_binds:
                    break
                name, val = var_binds[0]
                name_str = str(name).lstrip(".")
                if not name_str.startswith(base):
                    break
                results[name_str] = (
                    val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
                )
                current = ObjectType(name)
    except Exception as e:
        log.debug(f"SNMP WALK failed for {host}/{oid}: {e}")
    return results


def _walk_by_index(results: dict[str, str], base_oid: str) -> dict[str, str]:
    """Convert a walk result (keyed by full OID) into {index_suffix: value}.
    Tolerates leading dots and arbitrarily-deep instance suffixes."""
    out: dict[str, str] = {}
    base = base_oid.lstrip(".") + "."
    for full, val in results.items():
        clean = full.lstrip(".")
        if clean.startswith(base):
            out[clean[len(base):]] = val
    return out


# ── SNMP health monitor: stateful threshold + flap detection ───────────────────
#
# This is the bridge between raw polling and proactive alerting. Without it,
# concerning conditions (sustained CPU, link flaps, error rate spikes) would
# only be flagged if the analyzer LLM happened to flag them as "anomalous" in a
# batch review — which is unreliable and slow. The monitor enforces hard rules:
#
#   * link_down       — interface transitioned UP → DOWN since the last poll
#   * link_recovered  — interface transitioned DOWN → UP (notice, not alert)
#   * link_flap       — N transitions within FLAP_WINDOW seconds
#   * cpu_high        — avg_cpu over CPU_HIGH_PCT for CPU_HIGH_SAMPLES polls
#   * errors_high     — interface errors_per_sec over ERROR_RATE for 2 polls
#
# Each detected condition is returned as a structured dict. The poll loop emits
# them as Redis events (so the analyzer LLM still sees them) AND inserts them
# into the alerts table directly so the user sees them in the UI even if the
# LLM is offline.

SNMP_CPU_HIGH_PCT       = float(os.environ.get("SNMP_CPU_HIGH_PCT",       "85"))
SNMP_CPU_HIGH_SAMPLES   = int(  os.environ.get("SNMP_CPU_HIGH_SAMPLES",   "3"))
SNMP_FLAP_THRESHOLD     = int(  os.environ.get("SNMP_FLAP_THRESHOLD",     "3"))
SNMP_FLAP_WINDOW_SEC    = int(  os.environ.get("SNMP_FLAP_WINDOW_SEC",    "300"))
SNMP_ERROR_RATE_PER_SEC = float(os.environ.get("SNMP_ERROR_RATE_PER_SEC", "5"))
SNMP_ALERT_COOLDOWN_SEC = int(  os.environ.get("SNMP_ALERT_COOLDOWN_SEC", "600"))

# SFP / physical sensor thresholds
SNMP_SFP_TEMP_HIGH_C  = float(os.environ.get("SNMP_SFP_TEMP_HIGH_C",  "70"))   # warn
SNMP_SFP_TEMP_CRIT_C  = float(os.environ.get("SNMP_SFP_TEMP_CRIT_C",  "85"))   # high
SNMP_SFP_RX_LOW_DBM   = float(os.environ.get("SNMP_SFP_RX_LOW_DBM",   "-20"))  # RX power floor
SNMP_SFP_TX_LOW_DBM   = float(os.environ.get("SNMP_SFP_TX_LOW_DBM",   "-20"))  # TX power floor
SNMP_SFP_TX_DROP_DBM  = float(os.environ.get("SNMP_SFP_TX_DROP_DBM",  "3"))    # dBm drop from baseline

# Loopback / null interfaces are noisy and not worth alerting on.
_BORING_IFACES = {"lo", "lo0", "Null0", "Loopback0", "Loopback"}


class SnmpHealthMonitor:
    """Per-process state. State is keyed by host so multi-device polls don't
    cross-contaminate."""

    def __init__(self):
        # host → {idx → {"name": str, "status": "up"/"down",
        #                "transitions": [(ts, "up"/"down"), ...]}}
        self._iface_state: dict[str, dict[str, dict]] = {}
        # host → list of recent CPU readings (ts, value)
        self._cpu_history: dict[str, list[tuple[float, float]]] = {}
        # (host, idx) → last seen errors_per_sec (for 2-sample sustained check)
        self._error_history: dict[tuple[str, str], list[float]] = {}
        # (host, sensor_name) → first observed TX power (dBm) — drop baseline
        self._sfp_tx_baseline: dict[tuple[str, str], float] = {}

    def evaluate(self, host: str, sys_name: str,
                 interfaces: dict, avg_cpu: float | None) -> list[dict]:
        """Return a list of alert dicts to fire. Mutates internal state."""
        now = time.time()
        alerts: list[dict] = []

        # ── Interface link state machine ────────────────────────────────────
        prev_ifaces = self._iface_state.setdefault(host, {})
        for idx, iface in interfaces.items():
            name = iface.get("name") or f"if{idx}"
            if name in _BORING_IFACES:
                continue
            new_status = iface.get("oper_status") or "down"
            prev = prev_ifaces.get(idx)
            if prev is None:
                # First observation — record but don't fire (avoids spam at
                # startup when every interface is "new")
                prev_ifaces[idx] = {
                    "name": name,
                    "status": new_status,
                    "transitions": [],
                }
                continue

            if prev["status"] != new_status:
                prev["transitions"].append((now, new_status))
                # Trim to flap window
                cutoff = now - SNMP_FLAP_WINDOW_SEC
                prev["transitions"] = [t for t in prev["transitions"] if t[0] >= cutoff]
                prev["status"] = new_status

                if new_status == "down":
                    alerts.append({
                        "type": "link_down",
                        "severity": "high",
                        "host": host,
                        "sys_name": sys_name,
                        "target": name,
                        "title": f"Interface {name} is DOWN on {sys_name}",
                        "description": (
                            f"SNMP poll of {sys_name} ({host}) reports interface "
                            f"{name} transitioned to DOWN. Verify the cable, port "
                            f"configuration, and remote device."
                        ),
                        "value": None,
                    })
                else:  # came back up
                    alerts.append({
                        "type": "link_recovered",
                        "severity": "low",
                        "host": host,
                        "sys_name": sys_name,
                        "target": name,
                        "title": f"Interface {name} recovered on {sys_name}",
                        "description": (
                            f"Interface {name} on {sys_name} is back UP "
                            f"after a previous DOWN event."
                        ),
                        "value": None,
                    })

            # Flap detection — N transitions inside the rolling window
            if len(prev["transitions"]) >= SNMP_FLAP_THRESHOLD:
                alerts.append({
                    "type": "link_flap",
                    "severity": "high",
                    "host": host,
                    "sys_name": sys_name,
                    "target": name,
                    "title": f"Interface {name} is flapping on {sys_name}",
                    "description": (
                        f"Interface {name} on {sys_name} has changed state "
                        f"{len(prev['transitions'])} times in the last "
                        f"{SNMP_FLAP_WINDOW_SEC // 60} min. "
                        f"This usually indicates a bad cable, faulty SFP, "
                        f"duplex mismatch, or upstream device reboot loop."
                    ),
                    "value": len(prev["transitions"]),
                })
                # Reset so we don't re-fire every poll while transitions still
                # sit inside the window.
                prev["transitions"].clear()

        # Drop interfaces that disappeared from the device (renamed/removed)
        for idx in list(prev_ifaces.keys()):
            if idx not in interfaces:
                del prev_ifaces[idx]

        # ── CPU sustained-high detection ────────────────────────────────────
        if avg_cpu is not None:
            history = self._cpu_history.setdefault(host, [])
            history.append((now, avg_cpu))
            # Keep at most the last 20 samples (roughly 20 polls)
            del history[:-20]
            recent = history[-SNMP_CPU_HIGH_SAMPLES:]
            if (len(recent) >= SNMP_CPU_HIGH_SAMPLES
                    and all(v >= SNMP_CPU_HIGH_PCT for _, v in recent)):
                alerts.append({
                    "type": "cpu_high",
                    "severity": "medium",
                    "host": host,
                    "sys_name": sys_name,
                    "target": "system",
                    "title": f"CPU sustained over {SNMP_CPU_HIGH_PCT:.0f}% on {sys_name}",
                    "description": (
                        f"{sys_name} ({host}) has reported CPU >= "
                        f"{SNMP_CPU_HIGH_PCT:.0f}% for {SNMP_CPU_HIGH_SAMPLES} "
                        f"consecutive polls. Latest: {avg_cpu:.1f}%. Check "
                        f"running processes, traffic spikes, and recent config "
                        f"changes."
                    ),
                    "value": avg_cpu,
                })
                # Clear after firing so dedup is handled by alert table cooldown
                history.clear()

        # ── Interface error-rate detection ──────────────────────────────────
        for idx, iface in interfaces.items():
            name = iface.get("name") or f"if{idx}"
            if name in _BORING_IFACES:
                continue
            in_err = iface.get("in_errors_per_sec") or 0
            out_err = iface.get("out_errors_per_sec") or 0
            err_total = (in_err or 0) + (out_err or 0)
            if err_total <= 0:
                continue
            key = (host, idx)
            prev_errs = self._error_history.setdefault(key, [])
            prev_errs.append(err_total)
            del prev_errs[:-3]
            # Need at least 2 samples above threshold to call it sustained
            sustained = sum(1 for v in prev_errs if v >= SNMP_ERROR_RATE_PER_SEC)
            if sustained >= 2:
                alerts.append({
                    "type": "errors_high",
                    "severity": "medium",
                    "host": host,
                    "sys_name": sys_name,
                    "target": name,
                    "title": f"Interface {name} reporting {err_total:.1f} err/s on {sys_name}",
                    "description": (
                        f"Interface {name} on {sys_name} ({host}) has reported "
                        f">= {SNMP_ERROR_RATE_PER_SEC:.0f} errors/sec for at "
                        f"least 2 consecutive polls (current: in={in_err:.1f}, "
                        f"out={out_err:.1f}). Suggests a bad cable, NIC issue, "
                        f"or duplex mismatch."
                    ),
                    "value": err_total,
                })
                prev_errs.clear()

        return alerts

    def evaluate_sfp(self, host: str, sys_name: str,
                     sensors: list[dict]) -> list[dict]:
        """Check SFP/transceiver sensor readings against thresholds.
        Returns alert dicts — same shape as evaluate() output."""
        alerts: list[dict] = []
        for s in sensors:
            if not s.get("is_sfp"):
                continue
            name  = s["name"]
            stype = s["type"]
            val   = s["value"]

            if stype == "temperature":
                if val >= SNMP_SFP_TEMP_CRIT_C:
                    alerts.append({
                        "type": "sfp_temp_critical",
                        "severity": "high",
                        "host": host,
                        "sys_name": sys_name,
                        "target": name,
                        "title": f"SFP temperature critical: {name} = {val:.1f}°C on {sys_name}",
                        "description": (
                            f"SFP/transceiver {name!r} on {sys_name} ({host}) reports "
                            f"{val:.1f}°C — above critical threshold {SNMP_SFP_TEMP_CRIT_C:.0f}°C. "
                            f"Risk of permanent damage. Check cage airflow, cable bend radius, "
                            f"and clean the SFP cage immediately."
                        ),
                        "value": val,
                    })
                elif val >= SNMP_SFP_TEMP_HIGH_C:
                    alerts.append({
                        "type": "sfp_temp_high",
                        "severity": "medium",
                        "host": host,
                        "sys_name": sys_name,
                        "target": name,
                        "title": f"SFP temperature high: {name} = {val:.1f}°C on {sys_name}",
                        "description": (
                            f"SFP/transceiver {name!r} on {sys_name} ({host}) reports "
                            f"{val:.1f}°C (warn threshold {SNMP_SFP_TEMP_HIGH_C:.0f}°C). "
                            f"Check airflow and ensure the SFP cage is not obstructed."
                        ),
                        "value": val,
                    })

            elif stype == "optical_power":
                name_lc = name.lower()
                is_rx = "rx" in name_lc
                is_tx = "tx" in name_lc

                if is_rx and val < SNMP_SFP_RX_LOW_DBM:
                    alerts.append({
                        "type": "sfp_rx_power_low",
                        "severity": "medium",
                        "host": host,
                        "sys_name": sys_name,
                        "target": name,
                        "title": f"SFP RX power low: {name} = {val:.1f} dBm on {sys_name}",
                        "description": (
                            f"SFP {name!r} RX power {val:.1f} dBm is below threshold "
                            f"{SNMP_SFP_RX_LOW_DBM:.0f} dBm on {sys_name} ({host}). "
                            f"Likely causes: dirty connector, excessive bend radius, or a "
                            f"degraded remote transmitter. Clean fibre ends and inspect the run."
                        ),
                        "value": val,
                    })

                if is_tx:
                    bkey = (host, name)
                    if bkey not in self._sfp_tx_baseline:
                        self._sfp_tx_baseline[bkey] = val
                    elif val < self._sfp_tx_baseline[bkey] - SNMP_SFP_TX_DROP_DBM:
                        drop = self._sfp_tx_baseline[bkey] - val
                        alerts.append({
                            "type": "sfp_tx_power_drop",
                            "severity": "medium",
                            "host": host,
                            "sys_name": sys_name,
                            "target": name,
                            "title": f"SFP TX power drop: {name} dropped {drop:.1f} dBm on {sys_name}",
                            "description": (
                                f"SFP TX {name!r} on {sys_name} ({host}) has dropped "
                                f"{drop:.1f} dBm from its baseline "
                                f"({self._sfp_tx_baseline[bkey]:.1f} → {val:.1f} dBm). "
                                f"Indicates a degrading transmitter laser. "
                                f"Plan SFP replacement."
                            ),
                            "value": val,
                        })

                if not is_rx and not is_tx and val < SNMP_SFP_TX_LOW_DBM:
                    # Unlabelled optical power sensor below floor
                    alerts.append({
                        "type": "sfp_optical_power_low",
                        "severity": "low",
                        "host": host,
                        "sys_name": sys_name,
                        "target": name,
                        "title": f"SFP optical power low: {name} = {val:.1f} dBm on {sys_name}",
                        "description": (
                            f"Optical sensor {name!r} reading {val:.1f} dBm (threshold "
                            f"{SNMP_SFP_TX_LOW_DBM:.0f} dBm) on {sys_name} ({host})."
                        ),
                        "value": val,
                    })

        return alerts


_health_monitor = SnmpHealthMonitor()


_SEVERITY_TO_SYSLOG = {
    "critical": "crit",
    "high":     "err",
    "medium":   "warning",
    "low":      "notice",
}


async def _emit_snmp_alert_event(redis_client: aioredis.Redis, alert: dict) -> None:
    """Push an SNMP-derived alert into the normal event pipeline so the
    classifier keeps it (severity err/warning) and the analyzer can correlate."""
    syslog_sev = _SEVERITY_TO_SYSLOG.get(alert["severity"], "warning")
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": alert["host"],
        "source": "snmp_monitor",
        "severity": syslog_sev,
        "facility": "daemon",
        "program": "snmp_monitor",
        "message": alert["title"],
        "structured": {
            "type": "snmp_alert",
            "alert_type": alert["type"],
            "sys_name": alert.get("sys_name"),
            "target": alert.get("target"),
            "value": alert.get("value"),
            "severity": alert["severity"],
            "description": alert["description"],
        },
    }
    try:
        # SNMP alerts are always hi-priority: fired only when a threshold tripped.
        await streams.xadd_event(redis_client, streams.STREAM_HI, json.dumps(event))
    except Exception as e:
        log.warning(f"failed to emit SNMP alert event: {e}")


async def _insert_snmp_alert(pool: asyncpg.Pool | None, alert: dict) -> None:
    """Direct INSERT into alerts table with cooldown so the user sees the
    alert in the UI even if the analyzer LLM is offline. Mirrors the
    cooldown_key shape used by analyzer/main.py so the two paths dedup
    against each other naturally."""
    if pool is None:
        return
    cooldown_key = f"snmp:{alert['type']}:{alert['host']}:{alert.get('target','')}"
    title = alert["title"][:200]
    try:
        async with pool.acquire() as conn:
            existing = await conn.fetchrow(
                """SELECT id, seen_count FROM alerts
                   WHERE cooldown_key = $1
                     AND last_seen > NOW() - ($2 * INTERVAL '1 second')
                   ORDER BY last_seen DESC LIMIT 1""",
                cooldown_key, SNMP_ALERT_COOLDOWN_SEC,
            )
            if existing:
                await conn.execute(
                    "UPDATE alerts SET seen_count = $1, last_seen = NOW() "
                    "WHERE id = $2",
                    (existing["seen_count"] or 1) + 1, existing["id"],
                )
                return
            await conn.execute(
                """INSERT INTO alerts
                       (timestamp, severity, title, description,
                        affected_hosts, recommended_action, false_positive_risk,
                        event_count, raw_result, cooldown_key, seen_count, last_seen)
                   VALUES (NOW(), $1, $2, $3, $4, $5, 'low',
                           1, $6::jsonb, $7, 1, NOW())""",
                alert["severity"],
                title,
                alert["description"],
                [alert["host"]],
                _recommended_action_for(alert),
                json.dumps(alert),
                cooldown_key,
            )
    except Exception as e:
        log.warning(f"snmp alert insert failed for {alert['type']}: {e}")


def _recommended_action_for(alert: dict) -> str:
    t = alert["type"]
    if t == "link_down":
        return "Verify cable, port config, and remote device status"
    if t == "link_flap":
        return "Inspect cable/SFP for damage; check duplex and LACP config; review remote-device logs"
    if t == "cpu_high":
        return "Identify top processes via SSH/console; investigate traffic spike or runaway service"
    if t == "errors_high":
        return "Replace cable/SFP; verify duplex; check NIC driver/firmware"
    if t == "sfp_temp_critical":
        return "Shut down port immediately; check cage airflow; replace SFP if fault persists"
    if t == "sfp_temp_high":
        return "Check cage airflow; ensure no obstruction around SFP; monitor trend"
    if t in ("sfp_rx_power_low", "sfp_optical_power_low"):
        return "Clean fibre connectors; inspect bend radius; check remote transmitter power"
    if t == "sfp_tx_power_drop":
        return "Plan SFP replacement; check for connector contamination in the interim"
    return "Investigate device"


async def snmp_test(host: str, port: int, community: str) -> tuple[bool, str]:
    """Quick reachability + community check. Used by web UI test buttons."""
    try:
        result = await snmp_get(host, port, [OID_SYSTEM_DESCR, OID_SYSTEM_NAME], community)
        if not result:
            return False, "no response (timeout, wrong community, or device unreachable)"
        descr = result.get(OID_SYSTEM_DESCR, "")
        name = result.get(OID_SYSTEM_NAME, host)
        return True, f"{name}: {descr[:120]}"
    except Exception as e:
        return False, str(e)


async def poll_sfp_sensors(host: str, port: int,
                            community: str = SNMP_COMMUNITY) -> list[dict]:
    """Walk ENTITY-SENSOR-MIB (RFC 3433) + ENTITY-MIB to collect temperature
    and optical power (dBm) sensor readings.

    Returns a list of sensor dicts:
      {sensor_idx, name, descr, type, value, unit, is_sfp}
    type: "temperature" | "optical_power"
    is_sfp: True when the entity name suggests a fibre/SFP/DOM sensor.
    Returns [] if the device doesn't implement ENTITY-SENSOR-MIB.
    """
    # Probe sensor types first — skip devices that don't implement the MIB
    type_raw = await snmp_walk(host, port, OID_ENT_SENSOR_TYPE, community)
    if not type_raw:
        return []

    # Only fetch the rest when we know there's something to process
    scale_raw  = await snmp_walk(host, port, OID_ENT_SENSOR_SCALE, community)
    prec_raw   = await snmp_walk(host, port, OID_ENT_SENSOR_PREC,  community)
    value_raw  = await snmp_walk(host, port, OID_ENT_SENSOR_VALUE, community)
    name_raw   = await snmp_walk(host, port, OID_ENT_PHYS_NAME,    community)
    descr_raw  = await snmp_walk(host, port, OID_ENT_PHYS_DESCR,   community)

    types      = _walk_by_index(type_raw,  OID_ENT_SENSOR_TYPE)
    scales     = _walk_by_index(scale_raw, OID_ENT_SENSOR_SCALE)
    precs      = _walk_by_index(prec_raw,  OID_ENT_SENSOR_PREC)
    values     = _walk_by_index(value_raw, OID_ENT_SENSOR_VALUE)
    phys_names = _walk_by_index(name_raw,  OID_ENT_PHYS_NAME)
    phys_descr = _walk_by_index(descr_raw, OID_ENT_PHYS_DESCR)

    sensors: list[dict] = []
    for idx, type_str in types.items():
        try:
            sensor_type = int(type_str)
        except (ValueError, TypeError):
            continue
        if sensor_type not in (_SENSOR_TYPE_CELSIUS, _SENSOR_TYPE_DBM):
            continue

        raw_str = values.get(idx)
        if raw_str is None:
            continue
        try:
            raw_val = int(raw_str)
        except (ValueError, TypeError):
            continue

        scale = int(scales.get(idx) or "9")
        prec  = int(precs.get(idx)  or "0")
        actual = _apply_sensor_scale(raw_val, scale, prec)

        name  = (phys_names.get(idx) or f"sensor.{idx}").strip()
        descr = (phys_descr.get(idx) or "").strip()

        # Heuristic: mark as SFP if entity name/descr mentions optical/transceiver
        name_lower = (name + " " + descr).lower()
        is_sfp = any(kw in name_lower for kw in (
            "sfp", "transceiver", "xcvr", "optical", "dom",
            "tx power", "rx power", "tx pwr", "rx pwr",
            "laser", "fibre", "fiber", "xfp", "qsfp",
        ))

        sensors.append({
            "sensor_idx":  idx,
            "name":        name,
            "descr":       descr,
            "type":        "temperature" if sensor_type == _SENSOR_TYPE_CELSIUS else "optical_power",
            "value":       round(actual, 4),
            "unit":        "°C" if sensor_type == _SENSOR_TYPE_CELSIUS else "dBm",
            "is_sfp":      is_sfp,
        })

    return sensors


async def poll_arp_table(host: str, port: int,
                          community: str = SNMP_COMMUNITY) -> list[dict]:
    """Walk the device's ARP cache (IP-MIB ipNetToMediaTable).
    Returns [{ip, mac, type}] where type is 'dynamic'/'static'/'other'.

    Index structure: ifIndex.A.B.C.D — we derive the IP from the value of
    ipNetToMediaNetAddress which is cleaner than parsing the OID index.
    """
    addr_raw = await snmp_walk(host, port, OID_IP_NET_TO_MEDIA_ADDR, community)
    if not addr_raw:
        return []
    phys_raw = await snmp_walk(host, port, OID_IP_NET_TO_MEDIA_PHYS, community)
    type_raw = await snmp_walk(host, port, OID_IP_NET_TO_MEDIA_TYPE, community)

    addr_by_idx = _walk_by_index(addr_raw, OID_IP_NET_TO_MEDIA_ADDR)
    phys_by_idx = _walk_by_index(phys_raw, OID_IP_NET_TO_MEDIA_PHYS)
    type_by_idx = _walk_by_index(type_raw, OID_IP_NET_TO_MEDIA_TYPE)

    _TYPE_NAMES = {"1": "other", "2": "invalid", "3": "dynamic", "4": "static"}

    entries: list[dict] = []
    for idx, ip in addr_by_idx.items():
        ip = ip.strip()
        if not ip or ip in ("0.0.0.0", "255.255.255.255"):
            continue
        mac  = (phys_by_idx.get(idx) or "").strip()
        tval = (type_by_idx.get(idx)  or "3").strip()
        entries.append({
            "ip":  ip,
            "mac": mac,
            "type": _TYPE_NAMES.get(tval, "dynamic"),
        })
    return entries


async def _store_arp_topology(pool: asyncpg.Pool | None, device_host: str,
                               arp_entries: list[dict]) -> None:
    """Upsert ARP-derived IP→device mappings and topology edges into Postgres.
    This is the SNMP complement to the syslog source_ip mapping in the processor."""
    if pool is None or not arp_entries:
        return
    try:
        async with pool.acquire() as conn:
            for entry in arp_entries:
                ip = entry["ip"]
                # Record: this IP was seen in the ARP table of device_host
                await conn.execute("""
                    INSERT INTO host_ip_map (ip, host, source, confidence, first_seen, last_seen)
                    VALUES ($1, $2, 'snmp_arp', 0.8, NOW(), NOW())
                    ON CONFLICT (ip, host) DO UPDATE
                    SET last_seen  = NOW(),
                        confidence = GREATEST(host_ip_map.confidence, 0.8)
                """, ip, device_host)

                # Check if this IP belongs to a known syslog-sending host
                # If so, create a topology edge: device_host ←→ that syslog host
                row = await conn.fetchrow(
                    "SELECT host FROM host_ip_map WHERE ip = $1 AND source = 'syslog_source' LIMIT 1",
                    ip
                )
                if row and row["host"] != device_host:
                    syslog_host = row["host"]
                    await conn.execute("""
                        INSERT INTO topology_learned
                              (src_host, dst_host, relationship, evidence, confidence, event_count, first_seen, last_seen)
                        VALUES ($1, $2, 'arp_peer',
                                $3, 0.85, 1, NOW(), NOW())
                        ON CONFLICT (src_host, dst_host, relationship) DO UPDATE
                        SET last_seen   = NOW(),
                            event_count = topology_learned.event_count + 1,
                            confidence  = GREATEST(topology_learned.confidence, 0.85)
                    """, device_host, syslog_host,
                        f"{device_host} ARP cache shows {syslog_host} at {ip}")
    except Exception as e:
        log.debug(f"ARP topology store failed for {device_host}: {e}")


# Per-device-type OID profile. 'auto' polls everything; specific types skip
# OIDs that aren't relevant to that hardware to reduce noise + poll time.
DEVICE_TYPE_PROFILES: dict[str, dict] = {
    "auto":     {"interfaces": True,  "cpu": True,  "wifi": True,  "storage": True},
    "router":   {"interfaces": True,  "cpu": True,  "wifi": False, "storage": False},
    "switch":   {"interfaces": True,  "cpu": False, "wifi": False, "storage": False},
    "ap":       {"interfaces": True,  "cpu": False, "wifi": True,  "storage": False},
    "firewall": {"interfaces": True,  "cpu": True,  "wifi": False, "storage": False},
    "server":   {"interfaces": True,  "cpu": True,  "wifi": False, "storage": True},
}


async def insert_snmp_metric(pool: asyncpg.Pool | None, host: str, sys_name: str,
                              avg_cpu: float | None, wifi_clients: int,
                              interfaces: dict, now_iso: str,
                              sfp_sensors: list | None = None):
    if pool is None:
        return
    up_count = sum(1 for v in interfaces.values() if v.get("oper_status") == "up")
    down_count = sum(1 for v in interfaces.values() if v.get("oper_status") == "down")
    total_in = sum(v.get("in_bytes_per_sec") or 0 for v in interfaces.values())
    total_out = sum(v.get("out_bytes_per_sec") or 0 for v in interfaces.values())
    total_err = sum((v.get("in_errors_per_sec") or 0) + (v.get("out_errors_per_sec") or 0)
                    for v in interfaces.values())
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO snmp_metrics (timestamp, host, sys_name, avg_cpu, wifi_clients,
                                             interfaces_up, interfaces_down, total_in_bps,
                                             total_out_bps, total_errors, raw_data)
                   VALUES (NOW(), $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)""",
                host, sys_name, avg_cpu, wifi_clients,
                up_count, down_count, total_in, total_out, total_err,
                json.dumps({
                    "sys_name": sys_name,
                    "interfaces": interfaces,
                    "wifi_clients": wifi_clients,
                    "sfp_sensors": sfp_sensors or [],
                }),
            )
    except Exception as e:
        log.debug(f"snmp_metrics insert failed for {host}: {e}")


async def poll_device(device: dict, redis_client: aioredis.Redis,
                      pg_pool: asyncpg.Pool | None = None):
    """Poll a single device for system info + interface stats + wireless clients.
    Accepts a device dict from snmp_devices: host, port, community, device_type, label."""
    host = device["host"]
    port = device.get("port") or 161
    community = device.get("community") or SNMP_COMMUNITY
    device_type = (device.get("device_type") or "auto").lower()
    profile = DEVICE_TYPE_PROFILES.get(device_type, DEVICE_TYPE_PROFILES["auto"])
    label = device.get("label")

    now_iso = datetime.now(timezone.utc).isoformat()

    # ── System info (always) ───────────────────────────────────────────────────
    sys_info = await snmp_get(host, port, [OID_SYSTEM_DESCR, OID_SYSTEM_UPTIME, OID_SYSTEM_NAME], community)
    if not sys_info:
        await update_device_status(pg_pool, host, "unreachable",
                                    "no response to sysDescr (timeout or wrong community)")
        return
    sys_name = label or sys_info.get(OID_SYSTEM_NAME, host)
    uptime = sys_info.get(OID_SYSTEM_UPTIME, "?")

    # ── Interface descriptions + status ────────────────────────────────────────
    if profile["interfaces"]:
        descr_raw   = await snmp_walk(host, port, OID_IF_DESCR,          community)
        status_raw  = await snmp_walk(host, port, OID_IF_OPER_STATUS,    community)
        in_err_raw  = await snmp_walk(host, port, OID_IF_IN_ERRORS,      community)
        out_err_raw = await snmp_walk(host, port, OID_IF_OUT_ERRORS,     community)
        # Try HC (64-bit) counters first — more accurate on >100 Mbps links
        # and no wrap-around at ~50 GB (32-bit wraps in ~5 min at 1 Gbps)
        hc_in_raw   = await snmp_walk(host, port, OID_IFX_IN_HC_OCTETS,  community)
        hc_out_raw  = await snmp_walk(host, port, OID_IFX_OUT_HC_OCTETS, community)
        alias_raw   = await snmp_walk(host, port, OID_IFX_ALIAS,         community)
        speed_raw   = await snmp_walk(host, port, OID_IFX_SPEED_HIGH,    community)
        # Fall back to 32-bit counters when HC not supported
        in_oct_raw  = hc_in_raw  or await snmp_walk(host, port, OID_IF_IN_OCTETS,  community)
        out_oct_raw = hc_out_raw or await snmp_walk(host, port, OID_IF_OUT_OCTETS, community)
        use_hc_in   = bool(hc_in_raw)
        use_hc_out  = bool(hc_out_raw)
    else:
        descr_raw = status_raw = in_oct_raw = out_oct_raw = in_err_raw = out_err_raw = {}
        alias_raw = speed_raw = {}
        use_hc_in = use_hc_out = False

    descr_by_idx   = _walk_by_index(descr_raw,   OID_IF_DESCR)
    status_by_idx  = _walk_by_index(status_raw,  OID_IF_OPER_STATUS)
    in_oct_by_idx  = _walk_by_index(in_oct_raw,
                                     OID_IFX_IN_HC_OCTETS  if use_hc_in  else OID_IF_IN_OCTETS)
    out_oct_by_idx = _walk_by_index(out_oct_raw,
                                     OID_IFX_OUT_HC_OCTETS if use_hc_out else OID_IF_OUT_OCTETS)
    in_err_by_idx  = _walk_by_index(in_err_raw,  OID_IF_IN_ERRORS)
    out_err_by_idx = _walk_by_index(out_err_raw, OID_IF_OUT_ERRORS)
    alias_by_idx   = _walk_by_index(alias_raw,   OID_IFX_ALIAS)
    speed_by_idx   = _walk_by_index(speed_raw,   OID_IFX_SPEED_HIGH)

    interfaces: dict[str, dict] = {}
    for idx, descr_name in descr_by_idx.items():
        # Prefer ifAlias (user-set label e.g. "WAN1") over raw ifDescr for display
        alias = alias_by_idx.get(idx, "").strip()
        iface: dict = {
            "name":  alias if alias else descr_name,
            "descr": descr_name,
            "index": idx,
        }
        spd = speed_by_idx.get(idx, "")
        if spd.isdigit():
            iface["speed_mbps"] = int(spd)

        # ifOperStatus prettyPrints as "up"/"down"/"testing"/... in pysnmp 7,
        # but old builds may still return "1". Accept both.
        status_val = (status_by_idx.get(idx) or "").strip().lower()
        iface["oper_status"] = "up" if status_val in ("1", "up") else "down"

        counter_sources = (
            ("in_bytes",   in_oct_by_idx,  64 if use_hc_in  else 32),
            ("out_bytes",  out_oct_by_idx, 64 if use_hc_out else 32),
            ("in_errors",  in_err_by_idx,  32),
            ("out_errors", out_err_by_idx, 32),
        )
        for ckey, table_by_idx, cbits in counter_sources:
            counter_key = f"{ckey}_{host}_{idx}"
            raw = table_by_idx.get(idx)
            if raw and raw.isdigit():
                rate = calc_rate(host, counter_key, int(raw), bits=cbits)
                iface[ckey + "_per_sec"] = round(rate, 2) if rate is not None else None
                iface[ckey + "_total"] = int(raw)
            else:
                iface[ckey + "_per_sec"] = None

        interfaces[idx] = iface

    # ── Wireless clients (Unifi APs) ──────────────────────────────────────────
    total_wifi_clients = 0
    vap_details = {}
    if profile["wifi"]:
        wifi_clients = await snmp_walk(host, port, OID_UNIFI_VAP_CLIENTS, community)
        for oid_key, val in wifi_clients.items():
            if val.isdigit():
                vap_idx = oid_key.split(".")[-1]
                count = int(val)
                total_wifi_clients += count
                vap_details[vap_idx] = count

    # ── CPU load ──────────────────────────────────────────────────────────────
    avg_cpu = None
    if profile["cpu"]:
        cpu_loads = await snmp_walk(host, port, OID_HR_PROCESSOR_LOAD, community)
        if cpu_loads:
            loads = [int(v) for v in cpu_loads.values() if v.isdigit()]
            if loads:
                avg_cpu = round(sum(loads) / len(loads), 1)

    # ── SFP / physical sensor poll ────────────────────────────────────────────
    sfp_sensors: list[dict] = []
    try:
        sfp_sensors = await poll_sfp_sensors(host, port, community)
        if sfp_sensors:
            log.debug(f"SFP sensors on {host}: {len(sfp_sensors)} readings")
    except Exception as _sfp_err:
        log.debug(f"SFP sensor poll failed for {host}: {_sfp_err}")

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
    # SFP summary stats
    if sfp_sensors:
        sfp_temps = [s["value"] for s in sfp_sensors
                     if s["type"] == "temperature" and s["is_sfp"]]
        if sfp_temps:
            summary_parts.append(f"SFP_temp_max={max(sfp_temps):.1f}°C")
        rx_powers = [s["value"] for s in sfp_sensors
                     if s["type"] == "optical_power" and "rx" in s["name"].lower()]
        if rx_powers:
            summary_parts.append(f"SFP_rx_min={min(rx_powers):.1f}dBm")

    # Determine severity
    severity = "info"
    if down_ifaces or error_ifaces:
        severity = "warning"
    if avg_cpu and avg_cpu > 90:
        severity = "warning"
    # Escalate on concerning SFP readings
    for _s in sfp_sensors:
        if _s["is_sfp"] and _s["type"] == "temperature" and _s["value"] >= SNMP_SFP_TEMP_HIGH_C:
            severity = "warning"
        if (_s["is_sfp"] and _s["type"] == "optical_power"
                and "rx" in _s["name"].lower()
                and _s["value"] < SNMP_SFP_RX_LOW_DBM):
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
            "sfp_sensors": sfp_sensors,
            "hc_counters": use_hc_in or use_hc_out,
        },
    }

    # Regular polls are routine telemetry → low priority. Anything concerning
    # gets upgraded by the health check below via snmp_alert (hi).
    poll_sev = (severity or "info").lower()
    poll_queue = "loglm:raw:hi" if poll_sev in ("err", "error", "crit", "alert", "emerg") else "loglm:raw:lo"
    await redis_client.rpush(poll_queue, json.dumps(event))

    # ── Stateful health checks (flap/CPU/error thresholds) ───────────────────
    # These are evaluated AFTER the raw poll event is queued so the analyzer
    # sees both the baseline reading and the derived alerts in the same batch.
    health_alerts = _health_monitor.evaluate(host, sys_name, interfaces, avg_cpu)
    for ha in health_alerts:
        log.info(f"SNMP alert [{ha['severity']}] {ha['type']} {host}/{ha.get('target','')}: {ha['title']}")
        await _emit_snmp_alert_event(redis_client, ha)
        await _insert_snmp_alert(pg_pool, ha)

    sfp_alerts = _health_monitor.evaluate_sfp(host, sys_name, sfp_sensors)
    for sa in sfp_alerts:
        log.info(f"SFP alert [{sa['severity']}] {sa['type']} {host}/{sa.get('target','')}: {sa['title']}")
        await _emit_snmp_alert_event(redis_client, sa)
        await _insert_snmp_alert(pg_pool, sa)

    # ── ARP table → topology learning ────────────────────────────────────────
    # Routers/firewalls/switches have ARP caches that reveal which IPs are on
    # the same L3 segment.  We store these for the topology/chat agents.
    if profile.get("interfaces"):   # skip if interfaces not polled (e.g. bare sensors)
        try:
            arp_entries = await poll_arp_table(host, port, community)
            if arp_entries:
                log.debug(f"ARP: {host} has {len(arp_entries)} entries")
                await _store_arp_topology(pg_pool, host, arp_entries)
        except Exception as _arp_err:
            log.debug(f"ARP poll failed for {host}: {_arp_err}")

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
        "sfp_sensors": sfp_sensors,
    }
    await redis_client.hset("loglm:snmp_latest", host, json.dumps(metrics_snapshot))

    await insert_snmp_metric(pg_pool, host, sys_name, avg_cpu,
                             total_wifi_clients, interfaces, now_iso,
                             sfp_sensors=sfp_sensors)

    await update_device_status(pg_pool, host, "ok", None)

    log.info(f"Polled {sys_name}({host}) [{device_type}]: {len(interfaces)} ifs, "
             f"{len(down_ifaces)} down, {total_wifi_clients} wifi clients")


# ── Trap receiver ──────────────────────────────────────────────────────────────

# snmpTrapOID.0 — every v2c/v3 trap carries this varbind; for v1 traps pysnmp
# auto-translates the generic+specific trap fields into a v2 trap OID.
SNMP_TRAP_OID_VAR = "1.3.6.1.6.3.1.1.4.1.0"
SYS_UPTIME_VAR    = "1.3.6.1.2.1.1.3.0"

# Standard MIB-II / SNMPv2-MIB notifications. Keyed by trap OID.
# severity follows syslog convention (notice/warning/error). short = single-word
# tag for grouping; description is a human-readable label.
WELL_KNOWN_TRAPS: dict[str, dict[str, str]] = {
    "1.3.6.1.6.3.1.1.5.1": {"name": "coldStart",             "severity": "notice",  "desc": "device cold start (full reinitialization)"},
    "1.3.6.1.6.3.1.1.5.2": {"name": "warmStart",             "severity": "notice",  "desc": "device warm restart"},
    "1.3.6.1.6.3.1.1.5.3": {"name": "linkDown",              "severity": "warning", "desc": "interface transitioned to down"},
    "1.3.6.1.6.3.1.1.5.4": {"name": "linkUp",                "severity": "notice",  "desc": "interface transitioned to up"},
    "1.3.6.1.6.3.1.1.5.5": {"name": "authenticationFailure", "severity": "warning", "desc": "SNMP authentication failure (wrong community/credentials)"},
    "1.3.6.1.6.3.1.1.5.6": {"name": "egpNeighborLoss",       "severity": "warning", "desc": "EGP neighbor lost"},
    # BRIDGE-MIB
    "1.3.6.1.2.1.17.0.1": {"name": "newRoot",        "severity": "notice",  "desc": "spanning-tree new root elected"},
    "1.3.6.1.2.1.17.0.2": {"name": "topologyChange", "severity": "notice",  "desc": "spanning-tree topology change"},
    # ENTITY-MIB
    "1.3.6.1.2.1.47.2.0.1": {"name": "entConfigChange", "severity": "notice", "desc": "physical entity config changed"},
    # POWER-ETHERNET-MIB
    "1.3.6.1.2.1.105.0.1": {"name": "pethPsePortOnOffNotification", "severity": "notice",  "desc": "PoE port state changed"},
    "1.3.6.1.2.1.105.0.2": {"name": "pethMainPowerUsageOnNotification",  "severity": "warning", "desc": "PoE main power usage above threshold"},
    "1.3.6.1.2.1.105.0.3": {"name": "pethMainPowerUsageOffNotification", "severity": "notice",  "desc": "PoE main power usage back below threshold"},
}

# Human-readable OID labels for known varbinds (rendered in trap messages).
KNOWN_VARBIND_LABELS: dict[str, str] = {
    "1.3.6.1.2.1.2.2.1.1":  "ifIndex",
    "1.3.6.1.2.1.2.2.1.2":  "ifDescr",
    "1.3.6.1.2.1.2.2.1.7":  "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8":  "ifOperStatus",
    "1.3.6.1.2.1.31.1.1.1.1": "ifName",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
}


def _label_for_oid(oid: str) -> str:
    """Return a friendly label for an OID, or the OID itself.
    Strips the trailing instance-id (.N) when matching the table column OID."""
    if oid in KNOWN_VARBIND_LABELS:
        return KNOWN_VARBIND_LABELS[oid]
    # try parent OID (drop trailing index)
    parent = oid.rsplit(".", 1)[0]
    if parent in KNOWN_VARBIND_LABELS:
        return KNOWN_VARBIND_LABELS[parent]
    return oid


def _format_trap(trap_info: dict, varbinds: list[tuple[str, str]],
                 source_ip: str) -> tuple[str, str]:
    """Build (severity, message) for a decoded trap.
    trap_info: row from WELL_KNOWN_TRAPS or a synthetic one for unknown traps."""
    name = trap_info["name"]
    desc = trap_info["desc"]
    severity = trap_info["severity"]

    # Pull a few well-known varbinds for the message (interface info etc).
    extras = []
    for oid, val in varbinds:
        if oid in (SNMP_TRAP_OID_VAR, SYS_UPTIME_VAR):
            continue
        label = _label_for_oid(oid)
        if label != oid:  # only render named varbinds inline
            extras.append(f"{label}={val}")

    parts = [f"SNMP trap {name} from {source_ip}: {desc}"]
    if extras:
        parts.append("(" + ", ".join(extras[:6]) + ")")
    return severity, " ".join(parts)


async def _emit_trap_event(redis_client: aioredis.Redis, source_ip: str,
                            trap_oid: str, varbinds: list[tuple[str, str]]):
    info = WELL_KNOWN_TRAPS.get(trap_oid, {
        "name": "unknownTrap",
        "severity": "warning",
        "desc": f"unrecognized trap OID {trap_oid}",
    })
    severity, message = _format_trap(info, varbinds, source_ip)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": source_ip,
        "source": "snmp_trap",
        "severity": severity,
        "facility": "daemon",
        "program": "snmptrapd",
        "message": message,
        "structured": {
            "type": "snmp_trap",
            "trap_oid": trap_oid,
            "trap_name": info["name"],
            "trap_desc": info["desc"],
            "varbinds": [{"oid": o, "label": _label_for_oid(o), "value": v}
                         for o, v in varbinds],
        },
    }
    try:
        # SNMP traps are unsolicited — device decided something's worth telling
        # us. Always hi-priority.
        await streams.xadd_event(redis_client, streams.STREAM_HI, json.dumps(event))
    except Exception as e:
        log.warning(f"failed to push trap event: {e}")


async def start_trap_receiver(redis_client: aioredis.Redis):
    """Start the pysnmp NotificationReceiver on UDP 162.
    Decodes v1/v2c/v3 traps via the standard pysnmp engine pipeline.
    Returns the SnmpEngine so the caller can keep it alive."""
    try:
        from pysnmp.entity import engine as _engine, config as _config
        from pysnmp.carrier.asyncio.dgram import udp as _udp
        from pysnmp.entity.rfc3413 import ntfrcv as _ntfrcv
    except ImportError as e:
        log.warning(f"pysnmp ntfrcv unavailable, traps disabled: {e}")
        return None

    snmp_engine = _engine.SnmpEngine()

    # Bind UDP/162. UdpTransport API name varies a little across pysnmp 6/7.
    transport = _udp.UdpTransport().open_server_mode(("0.0.0.0", 162))
    add_transport = getattr(_config, "add_transport", None) or _config.addTransport
    add_transport(snmp_engine, _udp.DOMAIN_NAME, transport)

    # SNMPv1 + v2c community auth. The community name itself is not enforced —
    # we accept any community so long as the PDU decodes; processor/analyzer
    # decide whether the device is trusted.
    add_v1_system  = getattr(_config, "add_v1_system",  None) or _config.addV1System
    add_vacm_user  = getattr(_config, "add_vacm_user",  None) or _config.addVacmUser
    try:
        add_v1_system(snmp_engine, "loglm-area", SNMP_COMMUNITY)
    except Exception:
        pass  # already configured
    add_vacm_user(snmp_engine, 1, "loglm-area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
    add_vacm_user(snmp_engine, 2, "loglm-area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))

    loop = asyncio.get_running_loop()

    def _cb(snmp_engine_, state_reference, context_engine_id, context_name,
            var_binds, ctx):
        # Extract source IP from the execution context if available.
        source_ip = "unknown"
        try:
            obs = snmp_engine_.observer
            exec_ctx = obs.get_execution_context("rfc3412.receiveMessage:request")
            transport_addr = exec_ctx.get("transportAddress")
            if transport_addr:
                source_ip = str(transport_addr[0])
        except Exception:
            pass

        decoded: list[tuple[str, str]] = []
        trap_oid = ""
        for oid, val in var_binds:
            oid_str = str(oid)
            val_str = val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
            decoded.append((oid_str, val_str))
            if oid_str == SNMP_TRAP_OID_VAR:
                trap_oid = val_str

        # Schedule the async emit on the running loop — pysnmp callback is sync.
        loop.create_task(_emit_trap_event(redis_client, source_ip, trap_oid, decoded))

    _ntfrcv.NotificationReceiver(snmp_engine, _cb)
    log.info(f"SNMP trap receiver listening on UDP/162 (community={SNMP_COMMUNITY})")
    return snmp_engine


# ── Main loops ─────────────────────────────────────────────────────────────────

async def poll_loop(redis_client: aioredis.Redis, pg_pool: asyncpg.Pool | None):
    log.info(f"SNMP poller starting (DB-driven), interval={POLL_INTERVAL}s")
    while True:
        devices = await load_devices(pg_pool)
        if not devices:
            log.debug("No SNMP devices enabled — sleeping")
        else:
            tasks = [poll_device(d, redis_client, pg_pool) for d in devices]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    host = devices[i].get("host", "?")
                    log.warning(f"Poll failed for {host}: {result}")
                    await update_device_status(pg_pool, host, "error", str(result)[:200])
        await asyncio.sleep(POLL_INTERVAL)


async def poll_lldp(device: dict, pg_pool: asyncpg.Pool):
    """Poll LLDP neighbours from a device and upsert into lldp_neighbours + topology_edges."""
    host = device["host"]
    port = device.get("port") or 161
    community = device.get("community") or SNMP_COMMUNITY

    sys_names = await snmp_walk(host, port, OID_LLDP_REM_SYS_NAME, community)
    if not sys_names:
        return 0
    port_ids = await snmp_walk(host, port, OID_LLDP_REM_PORT_ID, community)

    count = 0
    for oid, remote_name in sys_names.items():
        if not remote_name or remote_name == "noSuchInstance":
            continue
        idx = oid.split(".")[-3:]
        remote_port = ""
        for pid_oid, pid_val in port_ids.items():
            if pid_oid.endswith(".".join(idx)):
                remote_port = str(pid_val)
                break
        local_port = idx[1] if len(idx) > 1 else ""
        try:
            async with pg_pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO lldp_neighbours (local_host, local_port, remote_host, remote_port, last_seen)
                       VALUES ($1, $2, $3, $4, NOW())
                       ON CONFLICT (local_host, local_port, remote_host) DO UPDATE
                       SET remote_port = $4, last_seen = NOW()""",
                    host, str(local_port), str(remote_name), remote_port,
                )
                await conn.execute(
                    """INSERT INTO topology_edges (from_host, to_host, label, auto)
                       VALUES ($1, $2, $3, TRUE)
                       ON CONFLICT DO NOTHING""",
                    host, str(remote_name), f"port {local_port}",
                )
            count += 1
        except Exception as e:
            log.debug(f"LLDP upsert failed for {host} → {remote_name}: {e}")
    if count:
        log.info(f"LLDP: {host} has {count} neighbours")
    return count


async def lldp_loop(redis_client, pg_pool: asyncpg.Pool):
    """Periodically poll all SNMP devices for LLDP neighbours."""
    await asyncio.sleep(30)
    while True:
        try:
            async with pg_pool.acquire() as conn:
                devices = await conn.fetch(
                    "SELECT host, port, community, device_type, label FROM snmp_devices WHERE enabled = TRUE"
                )
            for dev in devices:
                try:
                    await poll_lldp(dict(dev), pg_pool)
                except Exception as e:
                    log.debug(f"LLDP poll failed for {dev['host']}: {e}")
        except Exception as e:
            log.warning(f"LLDP loop failed: {e}")
        await asyncio.sleep(LLDP_POLL_INTERVAL)


async def main():
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

    pg_pool: asyncpg.Pool | None = None
    if POSTGRES_DSN:
        for _ in range(30):
            try:
                pg_pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=1, max_size=3)
                break
            except Exception:
                log.info("Waiting for Postgres...")
                await asyncio.sleep(2)

    if pg_pool is not None:
        try:
            await ensure_device_schema(pg_pool)
            await bootstrap_env_targets(pg_pool)
        except Exception as e:
            log.warning(f"snmp_devices schema/bootstrap failed: {e}")

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    trap_engine = None
    try:
        trap_engine = await start_trap_receiver(redis_client)
    except Exception as e:
        log.warning(f"Could not start trap receiver: {e}")

    lldp_task = None
    if pg_pool:
        lldp_task = asyncio.create_task(lldp_loop(redis_client, pg_pool))

    try:
        await poll_loop(redis_client, pg_pool)
    finally:
        if lldp_task:
            lldp_task.cancel()
        if trap_engine is not None:
            try:
                trap_engine.transportDispatcher.closeDispatcher()
            except Exception:
                pass
        if pg_pool:
            await pg_pool.close()


if __name__ == "__main__":
    asyncio.run(main())
