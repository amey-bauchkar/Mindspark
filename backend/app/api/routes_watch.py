"""Warrant Watch routes — /api/watch/*"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..config import get_settings
from ..watch import monitor, store
from ..watch.monitor import WatchError, watch_view
from ..watch.replay import REPLAY_LABEL, list_scenarios


def _require_watch_enabled() -> None:
    if not get_settings().watch_enabled:
        raise HTTPException(404, "Warrant Watch is disabled (WATCH_ENABLED=0)")


router = APIRouter(prefix="/api/watch", dependencies=[Depends(_require_watch_enabled)])


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except WatchError as exc:
        raise HTTPException(exc.status_code, str(exc))


async def _acall(fn, *args, **kwargs):
    try:
        return await fn(*args, **kwargs)
    except WatchError as exc:
        raise HTTPException(exc.status_code, str(exc))


@router.get("")
async def list_watches():
    settings = get_settings()
    return {
        "watches": [watch_view(w) for w in store.list_watches()],
        "config": {
            "interval_minutes": settings.watch_interval_minutes,
            "replay_interval_seconds": settings.watch_replay_interval_seconds,
            "scheduler_enabled": settings.watch_scheduler_enabled,
            "offline": settings.offline_fixtures,
        },
    }


@router.post("")
async def enable_watch(body: dict):
    report_id = str(body.get("report_id") or "")
    if not report_id:
        raise HTTPException(400, "Provide report_id")
    name = body.get("name")
    w = _call(monitor.enable_monitoring, report_id, str(name)[:120] if name else None)
    return watch_view(w, detail=True)


@router.get("/alerts")
async def alerts(limit: int = 5):
    """Unacknowledged security-change events across monitored projects (for in-app notification)."""
    statuses = ("active", "paused")
    events = store.list_events(unacknowledged_only=True, statuses=statuses, limit=max(1, min(limit, 50)))
    return {"unacknowledged": store.count_unacknowledged(statuses), "events": events}


@router.get("/scenarios")
async def scenarios():
    return {"label": REPLAY_LABEL, "scenarios": list_scenarios()}


@router.post("/demo")
async def create_demo(body: dict | None = None):
    scenario_id = str((body or {}).get("scenario_id") or "slack-action-axios-2026-04")
    w = await _acall(monitor.create_replay_demo, scenario_id)
    return watch_view(w, detail=True)


@router.get("/by-report/{report_id}")
async def watch_for_report(report_id: str):
    w = store.get_watch_for_report(report_id)
    return {
        "watch": watch_view(w, detail=True) if w else None,
        "eligibility": monitor.eligibility(report_id) if not w else {"eligible": True, "reason": None},
    }


@router.get("/{watch_id}")
async def get_watch(watch_id: str):
    return watch_view(_call(monitor.get_watch_or_404, watch_id), detail=True)


@router.post("/{watch_id}/check")
async def check_now(watch_id: str):
    result = await _acall(monitor.run_check, watch_id, "manual")
    return {**result, "watch": watch_view(monitor.get_watch_or_404(watch_id), detail=True)}


@router.post("/{watch_id}/pause")
async def pause(watch_id: str):
    return watch_view(_call(monitor.pause, watch_id), detail=True)


@router.post("/{watch_id}/resume")
async def resume(watch_id: str):
    return watch_view(_call(monitor.resume, watch_id), detail=True)


@router.post("/{watch_id}/disable")
async def disable(watch_id: str):
    return watch_view(_call(monitor.disable, watch_id), detail=True)


@router.post("/{watch_id}/replay/advance")
async def advance(watch_id: str):
    result = await _acall(monitor.advance_replay, watch_id)
    return {**result, "watch": watch_view(monitor.get_watch_or_404(watch_id), detail=True)}


@router.post("/{watch_id}/events/ack")
async def acknowledge(watch_id: str, body: dict | None = None):
    _call(monitor.get_watch_or_404, watch_id)
    ids = (body or {}).get("event_ids")
    ids = [str(i) for i in ids][:500] if isinstance(ids, list) else None
    return {"acknowledged": store.acknowledge_events(watch_id, ids)}
