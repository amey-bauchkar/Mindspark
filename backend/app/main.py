"""
Warrant backend — FastAPI application entry point.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .providers.cache import init_db, purge_expired
from .api import analyze_router, reports_router, misc_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    purge_expired()
    yield
    # Shutdown (nothing needed)


settings = get_settings()

app = FastAPI(
    title="Warrant — Software Supply Chain Risk Analyzer",
    description="Evidence-backed dependency analysis. One decision per risky dependency.",
    version="1.0.0-prototype",
    lifespan=lifespan,
)

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


@app.get("/")
async def root():
    return {"message": "Warrant API — see /docs for endpoints", "status": "ok"}
