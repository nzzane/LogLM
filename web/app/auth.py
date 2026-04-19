"""
Authentication + authorisation for the LogLM web UI.

Design decisions:
  * Local accounts only. No OAuth / SAML — this runs on a home LAN and we
    don't want to depend on an internet identity provider to log in. Users
    wanting SSO can front this with Authelia / Traefik ForwardAuth.
  * Passwords are bcrypt-hashed via passlib. Bcrypt is fine for the handful
    of logins a home monitor will see.
  * Sessions are HMAC-signed cookies (itsdangerous) + a server-side row in
    user_sessions. Cookie leak alone can't resurrect a session after logout
    because the server row is checked on every request.
  * API keys are long random secrets. Only the SHA-256 is stored, and only
    the first 8 chars are kept in clear for the listing UI.
  * CSRF: double-submit cookie + header. All mutating routes check it.
  * Loopback bypass: if LOGLM_AUTH_TRUST_LOOPBACK=1, connections from
    127.0.0.1 / ::1 bypass auth. Lets the processor / analyzer hit web APIs
    for health checks without juggling credentials.

Bootstrap:
  On first start, if the users table is empty AND LOGLM_BOOTSTRAP_ADMIN_PASSWORD
  is set, create an 'admin' user with that password. The env var should then
  be removed and the admin rotates their password from the UI.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
from fastapi import Cookie, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from passlib.context import CryptContext

log = logging.getLogger(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY", "")
AUTH_DISABLED = os.environ.get("LOGLM_AUTH_DISABLED", "0") in ("1", "true", "yes")
TRUST_LOOPBACK = os.environ.get("LOGLM_AUTH_TRUST_LOOPBACK", "1") in ("1", "true", "yes")
BOOTSTRAP_PW = os.environ.get("LOGLM_BOOTSTRAP_ADMIN_PASSWORD", "")
SESSION_COOKIE = "loglm_session"
CSRF_COOKIE = "loglm_csrf"
SESSION_LIFETIME = timedelta(hours=int(os.environ.get("LOGLM_SESSION_HOURS", "24")))

if not SECRET_KEY or SECRET_KEY == "changeme-in-production":
    # Still let the app start — just emit a loud warning. Home labs frequently
    # bring the stack up for the first time with the default.
    log.warning("SECRET_KEY is unset or default; sessions are NOT secure")
    if not SECRET_KEY:
        SECRET_KEY = secrets.token_urlsafe(32)

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
_signer = URLSafeTimedSerializer(SECRET_KEY, salt="loglm.session.v1")


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return _pwd.hash(pw)


def verify_password(pw: str, pw_hash: str) -> bool:
    try:
        return _pwd.verify(pw, pw_hash)
    except Exception:
        return False


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


# ── Principal returned from the dependency ────────────────────────────────────

@dataclass
class Principal:
    user_id: int | None
    username: str
    role: str
    method: str       # "session" | "apikey" | "loopback" | "disabled"

    def is_admin(self) -> bool:
        return self.role == "admin"

    def can_write(self) -> bool:
        return self.role == "admin"


ANON_LOOPBACK = Principal(user_id=None, username="loopback", role="admin", method="loopback")
ANON_DISABLED = Principal(user_id=None, username="anon", role="admin", method="disabled")


# ── User / session DB ops ─────────────────────────────────────────────────────

async def bootstrap_admin(pool: asyncpg.Pool) -> None:
    """If the users table is empty AND a bootstrap password is configured,
    create an 'admin' user so the first admin can log in. Logs a loud warning
    when this happens so the operator knows to remove the env var and rotate."""
    if not BOOTSTRAP_PW:
        return
    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM users")
        if count:
            return
        await conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')",
            "admin", hash_password(BOOTSTRAP_PW),
        )
    log.warning(
        "bootstrap admin created from LOGLM_BOOTSTRAP_ADMIN_PASSWORD — "
        "remove the env var and rotate the password immediately"
    )


async def create_user(pool: asyncpg.Pool, username: str, password: str, role: str) -> int:
    if role not in ("admin", "viewer"):
        raise ValueError("role must be admin or viewer")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
            username, hash_password(password), role,
        )
    return row["id"]


async def login_user(
    pool: asyncpg.Pool, username: str, password: str,
    ip: str | None, user_agent: str | None,
) -> tuple[str, Principal] | None:
    """Verify credentials, create a server-side session row, return (cookie_value, principal)."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, password_hash, role, disabled FROM users WHERE username = $1",
            username,
        )
        if row is None or row["disabled"]:
            return None
        if not verify_password(password, row["password_hash"]):
            return None

        token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + SESSION_LIFETIME
        await conn.execute(
            """INSERT INTO user_sessions (user_id, token_hash, ip, user_agent, expires_at)
               VALUES ($1, $2, $3::inet, $4, $5)""",
            row["id"], _token_hash(token), ip, (user_agent or "")[:300], expires,
        )
        await conn.execute("UPDATE users SET last_login = NOW() WHERE id = $1", row["id"])

    principal = Principal(
        user_id=row["id"], username=row["username"], role=row["role"], method="session",
    )
    # Wrap the raw token in an itsdangerous signature so cookie forgery is
    # impossible without the SECRET_KEY, even if token leak enumeration works.
    cookie = _signer.dumps({"t": token, "u": row["id"]})
    return cookie, principal


async def logout_session(pool: asyncpg.Pool, cookie_value: str) -> None:
    try:
        payload = _signer.loads(cookie_value, max_age=int(SESSION_LIFETIME.total_seconds()))
    except BadSignature:
        return
    token = payload.get("t")
    if not token:
        return
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE user_sessions SET revoked = TRUE WHERE token_hash = $1",
            _token_hash(token),
        )


async def resolve_session(pool: asyncpg.Pool, cookie_value: str) -> Principal | None:
    try:
        payload = _signer.loads(cookie_value, max_age=int(SESSION_LIFETIME.total_seconds()))
    except BadSignature:
        return None
    token = payload.get("t")
    if not token:
        return None
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT u.id, u.username, u.role
                 FROM user_sessions s JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = $1
                  AND NOT s.revoked
                  AND s.expires_at > NOW()
                  AND NOT u.disabled""",
            _token_hash(token),
        )
    if row is None:
        return None
    return Principal(
        user_id=row["id"], username=row["username"], role=row["role"], method="session",
    )


# ── API key ─────────────────────────────────────────────────────────────────

def _new_api_key() -> tuple[str, str, bytes]:
    raw = secrets.token_urlsafe(32)
    key = f"loglm_{raw}"
    return key, key[:14], _token_hash(key)


async def create_api_key(
    pool: asyncpg.Pool, name: str, scopes: list[str], created_by: int | None,
    ttl_days: int | None = None,
) -> str:
    """Returns the full key — only shown once to the caller."""
    key, prefix, digest = _new_api_key()
    expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)) if ttl_days else None
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO api_keys (name, key_prefix, key_hash, scopes, created_by, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)""",
            name, prefix, digest, scopes, created_by, expires,
        )
    return key


async def resolve_api_key(pool: asyncpg.Pool, raw: str) -> Principal | None:
    digest = _token_hash(raw)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT id, name, scopes
                 FROM api_keys
                WHERE key_hash = $1 AND NOT revoked
                  AND (expires_at IS NULL OR expires_at > NOW())""",
            digest,
        )
        if row is None:
            return None
        await conn.execute(
            "UPDATE api_keys SET last_used = NOW() WHERE id = $1", row["id"],
        )
    scopes = set(row["scopes"] or [])
    role = "admin" if "admin" in scopes else "viewer"
    return Principal(
        user_id=None, username=f"apikey:{row['name']}", role=role, method="apikey",
    )


# ── Audit log helper ──────────────────────────────────────────────────────────

async def audit(
    pool: asyncpg.Pool, principal: Principal | None, action: str,
    target: str | None = None, ip: str | None = None, detail: dict | None = None,
) -> None:
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO audit_log (user_id, username, action, target, ip, detail)
                   VALUES ($1, $2, $3, $4, $5::inet, $6::jsonb)""",
                principal.user_id if principal else None,
                principal.username if principal else None,
                action, target, ip,
                __import__("json").dumps(detail or {}),
            )
    except Exception as e:
        log.debug(f"audit log write failed: {e}")


# ── FastAPI dependency ────────────────────────────────────────────────────────

def _client_ip(request: Request) -> str | None:
    # Respect X-Forwarded-For only if the incoming socket is on loopback
    # (i.e., we're behind a trusted local reverse proxy). Never trust the
    # header from an arbitrary remote peer.
    direct = request.client.host if request.client else None
    if direct in ("127.0.0.1", "::1") and request.headers.get("x-forwarded-for"):
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return direct


def _is_loopback(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


async def current_user(
    request: Request,
    loglm_session: Optional[str] = Cookie(default=None),
) -> Principal:
    """Primary dependency used by protected routes."""
    if AUTH_DISABLED:
        return ANON_DISABLED

    ip = _client_ip(request)
    if TRUST_LOOPBACK and _is_loopback(ip):
        return ANON_LOOPBACK

    pool = request.app.state.pool
    # API key: Authorization: Bearer loglm_xxx  OR  X-API-Key: loglm_xxx
    auth_header = request.headers.get("authorization") or ""
    api_key = None
    if auth_header.lower().startswith("bearer "):
        api_key = auth_header[7:].strip()
    if not api_key:
        api_key = request.headers.get("x-api-key")
    if api_key and api_key.startswith("loglm_"):
        p = await resolve_api_key(pool, api_key)
        if p:
            return p

    if loglm_session:
        p = await resolve_session(pool, loglm_session)
        if p:
            return p

    raise HTTPException(status_code=401, detail="authentication required")


async def require_admin(user: Principal = Depends(current_user)) -> Principal:
    if not user.is_admin():
        raise HTTPException(status_code=403, detail="admin role required")
    return user


# ── CSRF (double-submit cookie) ───────────────────────────────────────────────

CSRF_HEADER = "x-csrf-token"
CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def issue_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE, token, httponly=False, samesite="lax",
        max_age=int(SESSION_LIFETIME.total_seconds()),
    )


async def csrf_guard(request: Request) -> None:
    """Call from any mutating route. Raises 403 on mismatch."""
    if AUTH_DISABLED:
        return
    if request.method not in CSRF_METHODS:
        return
    ip = _client_ip(request)
    if TRUST_LOOPBACK and _is_loopback(ip):
        return
    if request.headers.get("authorization", "").startswith("Bearer loglm_"):
        return  # API-key requests don't use cookies → no CSRF surface
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get(CSRF_HEADER)
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="invalid CSRF token")


# ── Rate limiting (simple Redis token bucket) ────────────────────────────────

async def rate_limit(
    request: Request, key: str, limit: int, window_s: int,
) -> None:
    """Apply a sliding token bucket per (key, client_ip). Uses Redis INCR with
    expiry for O(1) cost. Called from login + API endpoints."""
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        return
    ip = _client_ip(request) or "unknown"
    bucket = f"loglm:rl:{key}:{ip}"
    try:
        count = await redis.incr(bucket)
        if count == 1:
            await redis.expire(bucket, window_s)
        if count > limit:
            raise HTTPException(status_code=429, detail="rate limit exceeded")
    except HTTPException:
        raise
    except Exception as e:
        log.debug(f"rate limit check failed (allowing): {e}")
