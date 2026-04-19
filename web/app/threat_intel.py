"""
Offline-first threat intelligence + GeoIP.

Sources, in order of preference (each tried only if previously cached or
explicitly enabled by an env var — we never phone home without being told):

  1. Local MaxMind GeoLite2 MMDB (THREAT_INTEL_MMDB_PATH).
     Recommended on-prem source. Licensed free; update via geoipupdate cron.
  2. Local IP blocklists imported into blocklist_entries (firehol, spamhaus
     drop, emerging threats block). scripts/update_blocklists.py refreshes.
  3. AbuseIPDB API if THREAT_INTEL_ABUSEIPDB_KEY is set. Rate-limited.
  4. GreyNoise community API if THREAT_INTEL_GREYNOISE=1.

Everything is cached in Postgres (geoip_cache + threat_intel) so subsequent
lookups are free and never leak queries upstream.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
import httpx

log = logging.getLogger(__name__)

MMDB_PATH = os.environ.get("THREAT_INTEL_MMDB_PATH", "/data/geoip/GeoLite2-City.mmdb")
ASN_MMDB_PATH = os.environ.get("THREAT_INTEL_ASN_MMDB_PATH", "/data/geoip/GeoLite2-ASN.mmdb")
ABUSEIPDB_KEY = os.environ.get("THREAT_INTEL_ABUSEIPDB_KEY", "")
GREYNOISE_ENABLED = os.environ.get("THREAT_INTEL_GREYNOISE", "0") in ("1", "true", "yes")
CACHE_DAYS_OK = int(os.environ.get("THREAT_INTEL_CACHE_OK_DAYS", "30"))
CACHE_DAYS_BAD = int(os.environ.get("THREAT_INTEL_CACHE_BAD_DAYS", "7"))

_mmdb_reader = None
_asn_reader = None
_mmdb_lock = asyncio.Lock()


def _skip_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local \
            or addr.is_multicast or addr.is_unspecified or addr.is_reserved
    except ValueError:
        return True


async def _ensure_mmdb():
    """Lazy-load MaxMind readers. Missing MMDB is not an error — we just
    fall back to blocklist and external API paths."""
    global _mmdb_reader, _asn_reader
    if _mmdb_reader is not None:
        return
    async with _mmdb_lock:
        if _mmdb_reader is not None:
            return
        try:
            import maxminddb  # type: ignore
        except ImportError:
            log.info("maxminddb not installed; MMDB path disabled")
            return
        if os.path.exists(MMDB_PATH):
            try:
                _mmdb_reader = maxminddb.open_database(MMDB_PATH)
                log.info(f"GeoLite2-City mmdb loaded from {MMDB_PATH}")
            except Exception as e:
                log.warning(f"failed to open {MMDB_PATH}: {e}")
        if os.path.exists(ASN_MMDB_PATH):
            try:
                _asn_reader = maxminddb.open_database(ASN_MMDB_PATH)
                log.info(f"GeoLite2-ASN mmdb loaded from {ASN_MMDB_PATH}")
            except Exception as e:
                log.warning(f"failed to open {ASN_MMDB_PATH}: {e}")


async def lookup_geoip(
    pool: asyncpg.Pool, ip: str, http: httpx.AsyncClient | None = None,
) -> dict | None:
    """Return {country, city, lat, lon, asn, asn_org, source} or None."""
    if _skip_private(ip):
        return None
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT country, country_iso, city, lat, lon, asn, asn_org, source, expires_at "
            "FROM geoip_cache WHERE ip = $1::inet",
            ip,
        )
        if row and (row["expires_at"] is None or row["expires_at"] > datetime.now(timezone.utc)):
            return {k: row[k] for k in ("country", "country_iso", "city", "lat", "lon", "asn", "asn_org", "source")}

    # MaxMind MMDB path (offline, free).
    await _ensure_mmdb()
    found: dict | None = None
    if _mmdb_reader is not None:
        try:
            rec = _mmdb_reader.get(ip) or {}
            country = (rec.get("country") or {}).get("names", {}).get("en")
            country_iso = (rec.get("country") or {}).get("iso_code")
            city = (rec.get("city") or {}).get("names", {}).get("en")
            loc = rec.get("location") or {}
            found = {
                "country": country, "country_iso": country_iso, "city": city,
                "lat": loc.get("latitude"), "lon": loc.get("longitude"),
                "asn": None, "asn_org": None, "source": "maxmind",
            }
        except Exception as e:
            log.debug(f"mmdb lookup failed for {ip}: {e}")
    if found and _asn_reader is not None:
        try:
            asn_rec = _asn_reader.get(ip) or {}
            found["asn"] = asn_rec.get("autonomous_system_number")
            found["asn_org"] = asn_rec.get("autonomous_system_organization")
        except Exception:
            pass

    if found is None:
        return None

    expires = datetime.now(timezone.utc) + timedelta(days=CACHE_DAYS_OK)
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO geoip_cache (ip, country, country_iso, city, lat, lon,
                                         asn, asn_org, source, expires_at)
               VALUES ($1::inet,$2,$3,$4,$5,$6,$7,$8,$9,$10)
               ON CONFLICT (ip) DO UPDATE
                 SET country=$2, country_iso=$3, city=$4, lat=$5, lon=$6,
                     asn=$7, asn_org=$8, source=$9, expires_at=$10,
                     looked_up = NOW()""",
            ip, found["country"], found["country_iso"], found["city"],
            found["lat"], found["lon"], found["asn"], found["asn_org"],
            found["source"], expires,
        )
    return found


async def _check_blocklist(pool: asyncpg.Pool, ip: str) -> dict | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT list_name, category FROM blocklist_entries "
            "WHERE $1::inet <<= cidr ORDER BY masklen(cidr) DESC LIMIT 1",
            ip,
        )
    if row is None:
        return None
    return {
        "reputation": 80, "categories": [row["category"] or "blocklist"],
        "source": f"blocklist:{row['list_name']}", "detail": {},
    }


async def _check_abuseipdb(http: httpx.AsyncClient, ip: str) -> dict | None:
    if not ABUSEIPDB_KEY or not http:
        return None
    try:
        r = await http.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 30},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=6,
        )
        if r.status_code != 200:
            return None
        data = r.json().get("data") or {}
    except Exception as e:
        log.debug(f"abuseipdb lookup failed for {ip}: {e}")
        return None
    score = int(data.get("abuseConfidenceScore") or 0)
    cats: list[str] = []
    if data.get("totalReports"):
        cats.append("abuse")
    if data.get("isTor"):
        cats.append("tor")
    return {
        "reputation": score, "categories": cats, "source": "abuseipdb", "detail": data,
    }


async def _check_greynoise(http: httpx.AsyncClient, ip: str) -> dict | None:
    if not GREYNOISE_ENABLED or not http:
        return None
    try:
        r = await http.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=6)
        if r.status_code != 200:
            return None
        data = r.json() or {}
    except Exception as e:
        log.debug(f"greynoise lookup failed for {ip}: {e}")
        return None
    classification = data.get("classification") or ""
    score = {"malicious": 90, "suspicious": 60, "benign": 5}.get(classification, 0)
    return {
        "reputation": score, "categories": [classification] if classification else [],
        "source": "greynoise", "detail": data,
    }


async def lookup_threat(
    pool: asyncpg.Pool, ip: str, http: httpx.AsyncClient | None = None,
) -> dict | None:
    if _skip_private(ip):
        return None
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT reputation, categories, source, detail, expires_at "
            "FROM threat_intel WHERE ip = $1::inet", ip,
        )
        if row and (row["expires_at"] is None or row["expires_at"] > datetime.now(timezone.utc)):
            return {
                "reputation": row["reputation"], "categories": list(row["categories"] or []),
                "source": row["source"], "detail": row["detail"] or {},
            }

    for fn in (_check_blocklist, _check_abuseipdb, _check_greynoise):
        try:
            if fn is _check_blocklist:
                result = await fn(pool, ip)
            else:
                result = await fn(http, ip) if http else None
        except Exception as e:
            log.debug(f"threat lookup {fn.__name__} failed: {e}")
            result = None
        if result:
            rep = result["reputation"]
            ttl = CACHE_DAYS_BAD if rep >= 50 else CACHE_DAYS_OK
            expires = datetime.now(timezone.utc) + timedelta(days=ttl)
            async with pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO threat_intel (ip, reputation, categories, source, detail, expires_at)
                       VALUES ($1::inet,$2,$3,$4,$5::jsonb,$6)
                       ON CONFLICT (ip) DO UPDATE
                         SET reputation=$2, categories=$3, source=$4, detail=$5::jsonb,
                             expires_at=$6, looked_up=NOW()""",
                    ip, rep, result["categories"], result["source"],
                    __import__("json").dumps(result.get("detail") or {}), expires,
                )
            return result
    return None
