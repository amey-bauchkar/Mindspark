"""
Warrant — application configuration.
All settings read from environment / .env file.
"""
from __future__ import annotations
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    offline_fixtures: bool = False
    epss_threshold: float = 0.10
    freshness_hours: int = 72
    allowed_origins: str = "http://localhost:5173,http://localhost:3000"
    llm_provider: str = ""
    llm_api_key: str = ""
    db_path: str = "warrant_cache.db"

    # Warrant Watch — continuous security-evidence monitoring
    watch_enabled: bool = True              # Feature flag: snapshots, API routes, scheduler
    watch_scheduler_enabled: bool = True    # Background scheduler inside the API process
    watch_interval_minutes: float = 60.0    # Live monitoring: time between checks per project
    watch_replay_interval_seconds: float = 10.0  # Demo/replay watches: time between checks
    watch_tick_seconds: float = 5.0         # How often the scheduler looks for due checks
    watch_max_concurrent_checks: int = 3    # Projects checked in parallel per scheduler tick
    watch_notify_webhooks: str = ""         # Global channels for every project: "slack:https://…,teams:https://…,webhook:https://…"
    watch_webhook_secret: str = ""          # HMAC secret for global generic webhooks (X-Warrant-Signature)
    public_app_url: str = "http://localhost:5173"  # Base URL used for links in notifications

    # Access control (empty = open, for local use). Sent as header X-Warrant-Key or "Authorization: Bearer".
    warrant_api_key: str = ""               # Full access
    warrant_read_key: str = ""              # Read-only access (GET requests)

    # Registry metadata is fetched for this many direct dependencies (staleness / freshness signals)
    registry_fetch_cap: int = 50

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # Fixed outbound allowlist — never fetch from user-supplied URLs
    allowed_outbound_hosts: frozenset[str] = frozenset({
        "api.osv.dev",
        "api.deps.dev",
        "registry.npmjs.org",
        "api.first.org",
        "www.cisa.gov",
    })


@lru_cache
def get_settings() -> Settings:
    return Settings()
