"""
Warrant Watch scheduler — a single asyncio task inside each API process.

Every `watch_tick_seconds` it:
1. claims due checks atomically in the database (so several API processes / workers sharing one
   database never run the same check twice) and runs up to `watch_max_concurrent_checks` at once;
2. sends due notifications from the durable outbox.

Schedule state lives in the database, so restarting the app or the scheduler simply resumes;
duplicate alerts are prevented by the monitor's idempotent commit, not by timing.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import timedelta

from ..config import get_settings
from . import notify, store
from .monitor import WatchError, run_check

logger = logging.getLogger("warrant.watch")

CLAIM_LEASE = timedelta(minutes=15)  # A crashed process's claim expires and another process takes over


class WatchScheduler:
    def __init__(self, tick_seconds: float | None = None):
        self._tick_seconds = tick_seconds
        self._task: asyncio.Task | None = None
        self.last_tick_at: str | None = None
        self.last_tick_error: str | None = None

    @property
    def tick_seconds(self) -> float:
        return self._tick_seconds if self._tick_seconds is not None else get_settings().watch_tick_seconds

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def _check(self, watch_id: str) -> dict | None:
        try:
            return await run_check(watch_id, trigger="scheduled")
        except WatchError:
            return None  # Paused/disabled meanwhile, or a manual check is running
        except Exception:
            logger.exception("Warrant Watch: scheduled check failed for %s", watch_id)
            return None

    async def tick(self) -> list[dict]:
        """Run every due check once and send due notifications. Safe to call at any time."""
        now = store.utcnow()
        claimed = [wid for wid in store.list_due_watch_ids(now) if store.claim_due_watch(wid, now, now + CLAIM_LEASE)]
        sem = asyncio.Semaphore(max(1, get_settings().watch_max_concurrent_checks))

        async def bounded(wid: str):
            async with sem:
                return await self._check(wid)

        results = [r for r in await asyncio.gather(*(bounded(w) for w in claimed)) if r is not None]
        try:
            await notify.dispatch()
        except Exception:
            logger.exception("Warrant Watch: notification dispatch failed")
        self.last_tick_at = store.ts(store.utcnow())
        return results

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
                self.last_tick_error = None
            except Exception as exc:
                self.last_tick_error = type(exc).__name__
                logger.exception("Warrant Watch: scheduler tick failed")
            await asyncio.sleep(self.tick_seconds)

    def start(self) -> None:
        if not self.running:
            self._task = asyncio.create_task(self._loop(), name="warrant-watch-scheduler")
            logger.info("Warrant Watch scheduler started (tick %.0fs)", self.tick_seconds)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None


scheduler = WatchScheduler()
