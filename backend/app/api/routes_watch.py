"""Warrant Watch routes — /api/watch/*"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from ..config import get_settings
from ..watch import monitor, store
from ..watch.monitor import WatchError, watch_view
from ..watch.replay import REPLAY_LABEL, list_scenarios
from ..watch import notify
from ..security import MAX_UPLOAD_BYTES, sanitize_filename


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


@router.get("/health")
async def watch_health():
    """Operational status for monitoring dashboards / uptime checks."""
    from ..watch.scheduler import scheduler
    settings = get_settings()
    now = store.utcnow()
    return {
        "scheduler_enabled": settings.watch_scheduler_enabled,
        "scheduler_running": scheduler.running,
        "last_tick_at": scheduler.last_tick_at,
        "last_tick_error": scheduler.last_tick_error,
        "projects": len(store.list_watches()),
        "checks_due_now": store.count_due(now),
        "failing_projects": store.failing_watches(),
        "notifications": store.delivery_stats(),
        "global_channels": [notify.channel_view(c) for c in notify.global_channels()],
    }


async def _read_lockfile(file: UploadFile | None, text: str | None) -> tuple[str, str]:
    if file is not None:
        raw = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "File too large (max 5 MB)")
        return raw.decode("utf-8", errors="replace"), sanitize_filename(file.filename or "package-lock.json")
    if text:
        if len(text) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "Content too large (max 5 MB)")
        return text, "package-lock.json"
    raise HTTPException(400, "Provide the package-lock.json as a file or text")


@router.post("/sync")
async def sync_from_ci(project: str = Form(...), file: UploadFile | None = File(default=None),
                       text: str | None = Form(default=None)):
    """
    CI entry point. Call on every merge to the main branch: the first call creates the monitored
    project, later calls update its lockfile (history and alerts are kept).
    """
    content, filename = await _read_lockfile(file, text)
    result = await _acall(monitor.sync_lockfile, project, content, filename)
    w = monitor.get_watch_or_404(result["watch_id"])
    return {**result, "watch": watch_view(w)}


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


@router.post("/{watch_id}/lockfile")
async def update_lockfile(watch_id: str, file: UploadFile | None = File(default=None),
                          text: str | None = Form(default=None)):
    """Replace this project's monitored lockfile (new dependency versions), keeping its history."""
    content, filename = await _read_lockfile(file, text)
    result = await _acall(monitor.update_lockfile, watch_id, content, filename)
    return {**result, "watch": watch_view(monitor.get_watch_or_404(watch_id), detail=True)}


@router.post("/{watch_id}/settings")
async def settings(watch_id: str, body: dict):
    return watch_view(_call(monitor.update_settings, watch_id, body or {}), detail=True)


@router.post("/{watch_id}/delete")
async def delete(watch_id: str, body: dict | None = None):
    if not (body or {}).get("confirm"):
        raise HTTPException(400, 'Deleting a project removes its history and alerts — send {"confirm": true}')
    _call(monitor.delete_watch, watch_id)
    return {"deleted": watch_id}


@router.post("/{watch_id}/events/{event_id}/triage")
async def triage(watch_id: str, event_id: str, body: dict):
    return _call(monitor.triage, watch_id, event_id, str((body or {}).get("state", "")), (body or {}).get("note"))


@router.post("/{watch_id}/channels")
async def add_channel(watch_id: str, body: dict):
    _call(monitor.get_watch_or_404, watch_id)
    try:
        return notify.create_channel(watch_id, str(body.get("kind", "")), str(body.get("url", "")),
                                     str(body.get("min_priority") or "medium"), body.get("label"))
    except notify.ChannelError as exc:
        raise HTTPException(400, str(exc))


@router.post("/{watch_id}/channels/{channel_id}/delete")
async def remove_channel(watch_id: str, channel_id: str):
    if not store.delete_channel(watch_id, channel_id):
        raise HTTPException(404, "Channel not found for this project")
    return {"deleted": channel_id}


@router.post("/{watch_id}/channels/{channel_id}/test")
async def test_channel(watch_id: str, channel_id: str):
    ch = store.get_channel(channel_id)
    if ch is None or ch["watch_id"] != watch_id:
        raise HTTPException(404, "Channel not found for this project")
    return await notify.send_test(ch)
