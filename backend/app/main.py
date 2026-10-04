"""
Warrant backend — FastAPI application entry point.
"""
from __future__ import annotations

import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .config import get_settings
from .providers.cache import init_db, purge_expired
from .api import analyze_router, reports_router, misc_router, watch_router
from .watch.store import init_watch_db
from .watch.scheduler import scheduler as watch_scheduler
from .security import check_rate_limit


# ── Enterprise HTTP Security Headers ─────────────────────────────────────────
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' https://*.supabase.co https://api.osv.dev "
    "https://api.deps.dev https://api.first.org https://registry.npmjs.org; "
    "img-src 'self' data: https:; "
    "frame-ancestors 'none';"
)

_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    # Legacy XSS auditors are disabled per current OWASP guidance (CSP is the protection).
    "X-XSS-Protection": "0",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject enterprise security headers into every response."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response: Response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiting middleware.
    Delegates to security.check_rate_limit() so limits are configurable centrally.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        # Determine endpoint category: anything that parses uploads or calls external providers
        # shares the strict "upload" budget.
        path = request.url.path.rstrip("/")
        if request.method == "POST" and (
            path.startswith("/api/analyze")
            or path in ("/api/reports/import", "/api/watch/demo", "/api/watch/sync")
            or path.endswith(("/simulate-fix", "/check", "/lockfile", "/test"))
        ):
            category = "upload"
        elif path.endswith("/status"):
            category = "status"
        else:
            category = "general"

        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = check_rate_limit(category, client_ip)

        if not allowed:
            return Response(
                content='{"detail":"Too many requests. Please slow down."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(retry_after), **_SECURITY_HEADERS},
            )

        response: Response = await call_next(request)
        return response


# Endpoints that stay reachable without a key (uptime checks / the UI's "is a key required?" probe)
_OPEN_PATHS = {"/api/health", "/"}


def _presented_key(request: Request) -> str:
    key = request.headers.get("x-warrant-key", "")
    auth = request.headers.get("authorization", "")
    if not key and auth.lower().startswith("bearer "):
        key = auth[7:]
    return key.strip()


class ApiKeyMiddleware(BaseHTTPMiddleware):
    """
    Optional shared-key access control for every /api route.
    WARRANT_API_KEY grants full access; WARRANT_READ_KEY grants read-only (GET) access.
    With neither set the API is open (local, single-user use).
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        settings = get_settings()
        full, read = settings.warrant_api_key, settings.warrant_read_key
        path = request.url.path
        if (full or read) and request.method != "OPTIONS" and path.startswith("/api") and path not in _OPEN_PATHS:
            key = _presented_key(request)
            is_full = bool(full) and hmac.compare_digest(key.encode(), full.encode())
            is_read = bool(read) and hmac.compare_digest(key.encode(), read.encode())
            if not (is_full or (is_read and request.method in ("GET", "HEAD"))):
                status, detail = (403, "This key is read-only") if is_read else (401, "API key required")
                return Response(
                    content='{"detail":"%s"}' % detail, status_code=status, media_type="application/json",
                    headers={"WWW-Authenticate": "Bearer", **_SECURITY_HEADERS},
                )
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    init_watch_db()
    purge_expired()
    settings = get_settings()
    if settings.watch_enabled and settings.watch_scheduler_enabled:
        watch_scheduler.start()
    yield
    # Shutdown
    await watch_scheduler.stop()


settings = get_settings()

app = FastAPI(
    title="Warrant — Software Supply Chain Risk Analyzer",
    description="Evidence-backed dependency analysis. One decision per risky dependency.",
    version="1.0.0-prototype",
    lifespan=lifespan,
)

# Add middleware in order — outermost runs last on response
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ApiKeyMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "X-Warrant-Key", "Authorization"],
)

app.include_router(analyze_router)
app.include_router(reports_router)
app.include_router(misc_router)
app.include_router(watch_router)


@app.get("/")
async def root():
    return {"message": "Warrant API — see /docs for endpoints", "status": "ok"}
