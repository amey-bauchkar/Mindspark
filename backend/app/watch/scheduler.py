"""
Warrant Watch scheduler — a single asyncio task inside the API process.

Every `watch_tick_seconds` it runs the checks that are due (`next_check_at <= now`).
Schedule state lives in SQLite, so restarting the app or the scheduler simply resumes;
duplicate alerts are prevented by the monitor's idempotent commit, not by timing.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging

from ..config import get_settings
from . import store
from .monitor import WatchError, run_check

logger = logging.getLogger("warrant.watch")


class WatchScheduler:
    def __init__(self, tick_seconds: float | None = None):
        self._tick_seconds = tick_seconds
        self._task: asyncio.Task | None = None

    @property
    def tick_seconds(self) -> float:
        return self._tick_seconds if self._tick_seconds is not None else get_settings().watch_tick_seconds

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def tick(self) -> list[dict]:
        """Run every due check once (sequentially). Safe to call at any time."""
        results = []
        for watch_id in store.list_due_watch_ids(store.utcnow()):
            try:
                results.append(await run_check(watch_id, trigger="scheduled"))
            except WatchError:
                continue  # Paused/disabled meanwhile, or a manual check is running
            except Exception:
                logger.exception("Warrant Watch: scheduled check failed for %s", watch_id)
        return results

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:
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
