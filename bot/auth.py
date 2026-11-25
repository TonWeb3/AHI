"""Dashboard authentication, 24h HttpOnly session cookies, CSRF protection, and login rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from typing import Dict, Optional, Tuple

from fastapi import Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from bot.config import settings, verify_password

SESSION_TTL_SECONDS = 86400  # 24 hours (login once daily)
COOKIE_NAME_HTTP = "pm_session"
COOKIE_NAME_HTTPS = "__Host-pm_session"
LOGIN_CSRF_COOKIE = "pm_login_csrf"

# Rate limit: max 10 login attempts per 5 minutes per client IP
_RATE_WINDOW_S = 300.0
_RATE_MAX_ATTEMPTS = 10
_login_attempts: Dict[str, deque] = defaultdict(deque)

# Server-side session store: sha256(token) -> {"username": str, "expires_at": float}
_sessions: Dict[str, Dict[str, object]] = {}


def _is_https(request: Request) -> bool:
    xfp = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or xfp == "https"


def _cookie_name(request: Request) -> str:
    return COOKIE_NAME_HTTPS if _is_https(request) else COOKIE_NAME_HTTP


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _prune_sessions(now: Optional[float] = None) -> None:
    t = now if now is not None else time.time()
    expired = [k for k, v in _sessions.items() if float(v.get("expires_at", 0.0)) <= t]
    for k in expired:
        _sessions.pop(k, None)


def create_session(username: str) -> str:
    """Create a new 24-hour server-side session and return the raw cookie token."""
    _prune_sessions()
    token = secrets.token_urlsafe(32)
    _sessions[_token_hash(token)] = {
        "username": username,
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    return token


def _extract_session_token(cookies: Dict[str, str]) -> Optional[str]:
    return cookies.get(COOKIE_NAME_HTTPS) or cookies.get(COOKIE_NAME_HTTP)


def validate_session_cookies(cookies: Dict[str, str]) -> Optional[str]:
    """Return authenticated username if session cookie is valid and unexpired, else None."""
    if not auth_is_configured():
        return None
    token = _extract_session_token(cookies)
    if not token:
        return None
    th = _token_hash(token)
    sess = _sessions.get(th)
    if not sess:
        return None
    if float(sess.get("expires_at", 0.0)) <= time.time():
        _sessions.pop(th, None)
        return None
    return str(sess.get("username") or "")


def invalidate_all_sessions(username: Optional[str] = None) -> None:
    """Invalidate all active sessions (or all sessions for a given user) on logout."""
    if username is None:
        _sessions.clear()
        return
    to_del = [k for k, v in _sessions.items() if v.get("username") == username]
    for k in to_del:
        _sessions.pop(k, None)


def auth_is_configured() -> bool:
    return bool((getattr(settings, "AUTH_USERNAME", "") or "").strip() and (getattr(settings, "AUTH_PASSWORD_HASH", "") or "").strip())


def check_credentials(username: str, password: str) -> bool:
    """Constant-time verification of dashboard username and password."""
    if not auth_is_configured():
        return False
    expected_user = (getattr(settings, "AUTH_USERNAME", "") or "").strip()
    expected_hash = (getattr(settings, "AUTH_PASSWORD_HASH", "") or "").strip()
    user_ok = hmac.compare_digest((username or "").strip().encode("utf-8"), expected_user.encode("utf-8"))
    pw_ok = verify_password(password or "", expected_hash)
    return bool(user_ok and pw_ok)


def check_rate_limit(client_ip: str) -> Tuple[bool, int]:
    """Return (allowed, retry_after_seconds)."""
    now = time.time()
    q = _login_attempts[client_ip or "unknown"]
    while q and (now - q[0]) > _RATE_WINDOW_S:
        q.popleft()
    if len(q) >= _RATE_MAX_ATTEMPTS:
        retry = max(1, int(_RATE_WINDOW_S - (now - q[0])))
        return False, retry
    return True, 0


def record_failed_login(client_ip: str) -> None:
    _login_attempts[client_ip or "unknown"].append(time.time())


def clear_failed_logins(client_ip: str) -> None:
    _login_attempts.pop(client_ip or "unknown", None)


def set_session_cookie(response, request: Request, token: str) -> None:
    is_https = _is_https(request)
    # TODO(security): On plain HTTP 127.0.0.1, Secure flag is only set when served over HTTPS
    # (or behind an HTTPS reverse proxy with X-Forwarded-Proto: https) so local browser login works.
    response.set_cookie(
        key=_cookie_name(request),
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=is_https,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response, request: Request) -> None:
    for name in (COOKIE_NAME_HTTPS, COOKIE_NAME_HTTP):
        response.delete_cookie(key=name, path="/")


def issue_login_csrf(response, request: Request) -> str:
    csrf_tok = secrets.token_urlsafe(24)
    response.set_cookie(
        key=LOGIN_CSRF_COOKIE,
        value=csrf_tok,
        max_age=1800,
        httponly=True,
        secure=_is_https(request),
        samesite="lax",
        path="/login",
    )
    return csrf_tok


def verify_login_csrf(request: Request, form_csrf: str) -> bool:
    cookie_csrf = request.cookies.get(LOGIN_CSRF_COOKIE) or ""
    if not cookie_csrf or not form_csrf:
        return False
    return hmac.compare_digest(cookie_csrf.encode("utf-8"), form_csrf.encode("utf-8"))


def verify_websocket_auth(websocket: WebSocket) -> bool:
    """Return True iff the WebSocket handshake carries a valid session cookie."""
    return validate_session_cookies(dict(websocket.cookies)) is not None


def _same_origin_ok(request: Request) -> bool:
    """Verify Origin/Referer matches Host on state-changing requests to prevent CSRF."""
    host = (request.headers.get("host") or "").strip().lower()
    origin = (request.headers.get("origin") or "").strip().lower()
    if origin:
        # origin is e.g. http://127.0.0.1:8031
        parts = origin.split("://", 1)
        orig_host = parts[1].split("/", 1)[0] if len(parts) == 2 else ""
        return bool(host and orig_host == host)
    referer = (request.headers.get("referer") or "").strip().lower()
    if referer:
        parts = referer.split("://", 1)
        ref_host = parts[1].split("/", 1)[0] if len(parts) == 2 else ""
        return bool(host and ref_host == host)
    # SameSite=Lax + HttpOnly session cookie protects when browser omits Origin/Referer on same-origin
    return True


def _apply_security_headers(response, path: str) -> None:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if path == "/login" or path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"


class DashboardAuthMiddleware(BaseHTTPMiddleware):
    """Enforces 24h cookie authentication on all dashboard pages and API endpoints."""

    PUBLIC_PATHS = {"/login", "/favicon.ico"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path in self.PUBLIC_PATHS:
            response = await call_next(request)
            _apply_security_headers(response, path)
            return response

        user = validate_session_cookies(dict(request.cookies))
        if not user:
            if path.startswith("/api/") or path == "/history":
                resp = JSONResponse({"error": "authentication_required"}, status_code=401)
            else:
                resp = RedirectResponse(url="/login", status_code=303)
            _apply_security_headers(resp, path)
            return resp

        # Reject cross-origin state-changing requests (CSRF defense-in-depth)
        if request.method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            if not _same_origin_ok(request):
                resp = JSONResponse({"error": "csrf_origin_mismatch"}, status_code=403)
                _apply_security_headers(resp, path)
                return resp

        request.state.auth_user = user
        response = await call_next(request)
        _apply_security_headers(response, path)
        return response
