"""
Warrant backend — FastAPI application entry point.
"""
from __future__ import annotations

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
    "X-XSS-Protection": "1; mode=block",
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
        # Determine endpoint category
        path = request.url.path
        if path.startswith("/api/analyze"):
            category = "upload"
        elif "/status" in path:
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
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)

app.include_router(analyze_router)
app.include_router(reports_router)
app.include_router(misc_router)
app.include_router(watch_router)


@app.get("/")
async def root():
    return {"message": "Warrant API — see /docs for endpoints", "status": "ok"}
