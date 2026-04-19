"""
GeoIP enrichment using MaxMind MMDB files.

Adds country, city, ASN to firewall flow events when MMDB files are available.
Falls back gracefully when files don't exist — no hard dependency.
"""

import ipaddress
import logging
import os

log = logging.getLogger(__name__)

CITY_PATH = os.environ.get("THREAT_INTEL_MMDB_PATH", "")
ASN_PATH = os.environ.get("THREAT_INTEL_ASN_MMDB_PATH", "")

_city_reader = None
_asn_reader = None
_loaded = False

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
]


def init():
    global _city_reader, _asn_reader, _loaded
    if _loaded:
        return
    _loaded = True
    try:
        import maxminddb
    except ImportError:
        log.info("maxminddb not installed — GeoIP enrichment disabled")
        return
    if CITY_PATH and os.path.isfile(CITY_PATH):
        try:
            _city_reader = maxminddb.open_database(CITY_PATH)
            log.info(f"GeoIP city DB loaded: {CITY_PATH}")
        except Exception as e:
            log.warning(f"GeoIP city load failed: {e}")
    if ASN_PATH and os.path.isfile(ASN_PATH):
        try:
            _asn_reader = maxminddb.open_database(ASN_PATH)
            log.info(f"GeoIP ASN DB loaded: {ASN_PATH}")
        except Exception as e:
            log.warning(f"GeoIP ASN load failed: {e}")


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918)
    except ValueError:
        return True


def enrich(ip: str) -> dict:
    """Return GeoIP data for an IP. Empty dict if unavailable or private."""
    if not ip or _is_private(ip):
        return {}
    result = {}
    if _city_reader:
        try:
            data = _city_reader.get(ip)
            if data:
                country = data.get("country", {})
                city = data.get("city", {})
                loc = data.get("location", {})
                result["country"] = country.get("iso_code", "")
                result["country_name"] = country.get("names", {}).get("en", "")
                result["city"] = city.get("names", {}).get("en", "")
                result["latitude"] = loc.get("latitude")
                result["longitude"] = loc.get("longitude")
        except Exception:
            pass
    if _asn_reader:
        try:
            data = _asn_reader.get(ip)
            if data:
                result["asn"] = data.get("autonomous_system_number")
                result["asn_org"] = data.get("autonomous_system_organization", "")
        except Exception:
            pass
    return result


def enrich_event(event: dict) -> dict:
    """Add GeoIP fields to a firewall event's structured data."""
    s = event.get("structured") or {}
    if s.get("type") != "firewall_event":
        return event
    for field in ("src_ip", "dst_ip"):
        ip = s.get(field)
        if ip:
            geo = enrich(str(ip))
            if geo:
                s[f"{field}_geo"] = geo
    return event
