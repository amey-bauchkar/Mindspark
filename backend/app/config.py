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
