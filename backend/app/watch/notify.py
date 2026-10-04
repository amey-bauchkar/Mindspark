"""
Warrant Watch notifications — Slack, Microsoft Teams and signed generic webhooks.

Delivery uses a durable outbox (`watch_deliveries`): every (message, channel) pair is inserted
idempotently and retried with backoff until it is delivered or given up, and the result is
visible per project. Messages are queued when a check commits its events, and the outbox is
reconciled on every scheduler tick, so a crash between the two never loses a notification and a
restart never sends one twice.

Safety:
- Only https URLs whose host resolves to a public address; redirects are not followed.
- Channel URLs are secrets: masked in every API response and never logged.
- Generic webhooks are signed: header X-Warrant-Signature: sha256=<HMAC of the body>.
- Text from provider data is escaped for Slack/Teams markup (no injected @channel mentions).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse

import httpx

from ..config import get_settings
from ..security import verify_safe_outbound_ip
from . import store
from .store import ts, utcnow

logger = logging.getLogger("warrant.watch.notify")

KINDS = ("slack", "teams", "webhook")
PRIORITIES = ("info", "low", "medium", "high")
PRIORITY_RANK = {p: i for i, p in enumerate(PRIORITIES)}
MAX_ATTEMPTS = 6
BACKOFF_SECONDS = (30, 120, 600, 1800, 3600)
SEND_TIMEOUT = 10.0
FAILURE_ALERT_STREAK = 3  # Consecutive failed checks before "monitoring is failing" is sent

_SLACK_HOSTS = ("hooks.slack.com",)
_TEAMS_SUFFIXES = (".webhook.office.com", ".logic.azure.com", ".environment.api.powerplatform.com")


class ChannelError(ValueError):
    pass


# ─── Channel validation & views ───────────────────────────────────────────────

def validate_channel(kind: str, url: str, min_priority: str) -> tuple[str, str, str]:
    kind = (kind or "").strip().lower()
    if kind not in KINDS:
        raise ChannelError(f"Channel type must be one of: {', '.join(KINDS)}")
    if min_priority not in PRIORITIES:
        raise ChannelError(f"Minimum priority must be one of: {', '.join(PRIORITIES)}")
    url = (url or "").strip()
    if not url or len(url) > 2048:
        raise ChannelError("Provide the channel URL")
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        raise ChannelError("Channel URL must be an https:// URL")
    if parsed.username or parsed.password:
        raise ChannelError("Channel URL must not contain credentials")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise ChannelError("Channel URL must point to a public host")
    if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        raise ChannelError("Channel URL must point to a public host")
    if kind == "slack" and host not in _SLACK_HOSTS:
        raise ChannelError("Slack channels must be incoming-webhook URLs (https://hooks.slack.com/…)")
    if kind == "teams" and not host.endswith(_TEAMS_SUFFIXES):
        raise ChannelError("Teams channels must be Teams incoming-webhook or Workflows URLs")
    return kind, url, min_priority


def mask_url(url: str) -> str:
    parsed = urlparse(url)
    tail = url[-4:] if len(url) > 12 else ""
    return f"{parsed.scheme}://{parsed.hostname}/…{tail}"


def channel_view(ch: dict) -> dict:
    return {
        "id": ch["id"],
        "kind": ch["kind"],
        "label": ch.get("label"),
        "min_priority": ch["min_priority"],
        "enabled": bool(ch.get("enabled", 1)),
        "created_at": ch.get("created_at"),
        "url": mask_url(ch["url"]),
        "signed": bool(ch.get("secret")),
        "source": ch.get("source", "project"),
    }


def global_channels() -> list[dict]:
    """Channels for every project from WATCH_NOTIFY_WEBHOOKS ("slack:https://…,webhook:https://…")."""
    out = []
    for item in (get_settings().watch_notify_webhooks or "").split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        kind, url = item.split(":", 1)
        try:
            kind, url, _ = validate_channel(kind, url, "medium")
        except ChannelError as exc:
            logger.warning("Ignoring invalid WATCH_NOTIFY_WEBHOOKS entry (%s): %s", kind, exc)
            continue
        out.append({
            "id": "global:" + hashlib.sha256(url.encode()).hexdigest()[:16], "watch_id": None, "kind": kind,
            "url": url, "secret": get_settings().watch_webhook_secret or None, "min_priority": "medium",
            "label": "Global (WATCH_NOTIFY_WEBHOOKS)", "enabled": 1, "created_at": None, "source": "global",
        })
    return out


def _channels_for(watch_id: str) -> list[dict]:
    return [c for c in store.list_channels(watch_id) if c["enabled"]] + global_channels()


def _resolve_channel(key: str) -> dict | None:
    if key.startswith("global:"):
        return next((c for c in global_channels() if c["id"] == key), None)
    return store.get_channel(key)


def create_channel(watch_id: str, kind: str, url: str, min_priority: str = "medium", label: str | None = None) -> dict:
    kind, url, min_priority = validate_channel(kind, url, min_priority)
    ch = {
        "id": str(uuid.uuid4()), "watch_id": watch_id, "kind": kind, "url": url,
        "secret": secrets.token_hex(32) if kind == "webhook" else None,
        "min_priority": min_priority, "label": (label or "")[:80] or None, "created_at": ts(utcnow()),
    }
    store.create_channel(ch)
    view = channel_view(ch)
    if ch["secret"]:
        view["signing_secret"] = ch["secret"]  # Shown once, at creation
    return view


# ─── Messages ─────────────────────────────────────────────────────────────────

def _link(report_id: str | None) -> str | None:
    if not report_id:
        return None
    return f"{get_settings().public_app_url.rstrip('/')}/report/{report_id}"


def _label(v: str) -> str:
    return {"ACT_NOW": "ACT NOW", "NO_KNOWN_FINDING": "NO KNOWN FINDING", "CANNOT_ASSESS": "CANNOT ASSESS"}.get(v, v)


def event_payload(ev: dict) -> dict:
    sim = " [DEMO / REPLAY / SIMULATED EVENT]" if ev.get("simulated") else ""
    title = f"SECURITY CHANGE DETECTED{sim}: {ev['package']}@{ev['version']}"
    text = (f"{_label(ev['previous']['verdict'])} → {_label(ev['current']['verdict'])} "
            f"({ev['priority']} priority) in {ev['project']}. " + " ".join(ev.get("reason_lines") or [])[:900])
    return {
        "type": "security_change",
        "title": title,
        "text": text,
        "priority": ev["priority"],
        "link": _link(ev.get("report_id")),
        "event": {k: ev.get(k) for k in (
            "id", "watch_id", "project", "subject", "package", "version", "change_type", "priority", "previous",
            "current", "reason", "evidence_sources", "detected_at", "evidence_as_of", "report_id", "simulated", "label",
        )},
        "changed_evidence": [{k: e.get(k) for k in ("id", "change", "source", "origin", "published_at", "url")}
                             for e in (ev.get("changed_evidence") or [])][:20],
    }


def health_payload(w: dict, check: dict, *, recovered: bool) -> dict:
    if recovered:
        title = f"Warrant Watch: monitoring recovered for {w['name']}"
        text = f"Checks are completing again. Latest: {check['summary']}"
    else:
        title = f"Warrant Watch: monitoring is FAILING for {w['name']}"
        text = (f"{FAILURE_ALERT_STREAK} consecutive checks failed; the project is not being monitored. "
                f"Latest: {check['summary']}")
    return {"type": "monitoring_recovered" if recovered else "monitoring_failure", "title": title, "text": text,
            "priority": "info" if recovered else "high", "link": _link(w.get("latest_report_id")),
            "watch_id": w["id"], "project": w["name"], "check_id": check["id"]}


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(kind: str, payload: dict, secret: str | None, delivery_id: str) -> tuple[bytes, dict]:
    if kind == "slack":
        link = f"\n<{payload['link']}|View updated analysis>" if payload.get("link") else ""
        body = {"text": f"*{_esc(payload['title'])}*\n{_esc(payload['text'])}{link}"}
    elif kind == "teams":
        body = {
            "@type": "MessageCard", "@context": "https://schema.org/extensions",
            "summary": _esc(payload["title"])[:150],
            "themeColor": {"high": "B91C1C", "medium": "B45309", "low": "1D4ED8"}.get(payload.get("priority"), "64748B"),
            "title": _esc(payload["title"]), "text": _esc(payload["text"]),
        }
        if payload.get("link"):
            body["potentialAction"] = [{"@type": "OpenUri", "name": "View updated analysis",
                                        "targets": [{"os": "default", "uri": payload["link"]}]}]
    else:
        body = payload
    raw = json.dumps(body, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "Warrant-Watch/1.0",
               "X-Warrant-Event": payload.get("type", ""), "X-Warrant-Delivery": delivery_id}
    if kind == "webhook" and secret:
        headers["X-Warrant-Signature"] = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return raw, headers


# ─── Queueing ─────────────────────────────────────────────────────────────────

def queue_events(watch_id: str, events: list[dict]) -> int:
    queued = 0
    now = utcnow()
    for ch in _channels_for(watch_id):
        for ev in events:
            if PRIORITY_RANK.get(ev["priority"], 0) >= PRIORITY_RANK[ch["min_priority"]]:
                queued += store.enqueue_delivery(ref=f"event:{ev['id']}", channel_key=ch["id"], watch_id=watch_id,
                                                 payload=event_payload(ev), now=now)
    return queued


def queue_health(w: dict, check: dict, *, recovered: bool) -> int:
    queued = 0
    payload = health_payload(w, check, recovered=recovered)
    for ch in _channels_for(w["id"]):
        # "Monitoring is failing" always goes out; "recovered" follows the channel's priority filter
        if not recovered or PRIORITY_RANK[payload["priority"]] >= PRIORITY_RANK[ch["min_priority"]]:
            queued += store.enqueue_delivery(ref=f"health:{check['id']}", channel_key=ch["id"], watch_id=w["id"],
                                             payload=payload, now=utcnow())
    return queued


def reconcile() -> int:
    """Queue any committed event a channel should have received (e.g. after a crash before queueing)."""
    queued = 0
    for ch in store.list_channels():
        if ch["enabled"]:
            evs = [e for e in store.events_since(ch["created_at"], ch["watch_id"])
                   if PRIORITY_RANK.get(e["priority"], 0) >= PRIORITY_RANK[ch["min_priority"]]]
            for ev in evs:
                queued += store.enqueue_delivery(ref=f"event:{ev['id']}", channel_key=ch["id"],
                                                 watch_id=ch["watch_id"], payload=event_payload(ev), now=utcnow())
    since = ts(utcnow() - timedelta(hours=1))
    for ch in global_channels():
        for ev in store.events_since(since):
            if PRIORITY_RANK.get(ev["priority"], 0) >= PRIORITY_RANK[ch["min_priority"]]:
                queued += store.enqueue_delivery(ref=f"event:{ev['id']}", channel_key=ch["id"],
                                                 watch_id=ev["watch_id"], payload=event_payload(ev), now=utcnow())
    return queued


# ─── Sending ──────────────────────────────────────────────────────────────────

async def _send(ch: dict, payload: dict, delivery_id: str) -> tuple[bool, bool, str | None]:
    """Returns (delivered, retryable, error)."""
    host = urlparse(ch["url"]).hostname or ""
    if not await asyncio.to_thread(verify_safe_outbound_ip, host):
        return False, True, f"{host} did not resolve to a public address"
    body, headers = render(ch["kind"], payload, ch.get("secret"), delivery_id)
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=SEND_TIMEOUT) as client:
            resp = await client.post(ch["url"], content=body, headers=headers)
    except httpx.HTTPError as exc:
        return False, True, f"network error ({type(exc).__name__})"
    if 200 <= resp.status_code < 300:
        return True, False, None
    retryable = resp.status_code == 429 or resp.status_code >= 500
    return False, retryable, f"HTTP {resp.status_code}"


async def dispatch(limit: int = 50) -> dict:
    """Send due notifications. Safe to run concurrently from several processes (claims are atomic)."""
    reconcile()
    sent = failed = 0
    now = utcnow()
    for d in store.due_deliveries(now, limit):
        if not store.claim_delivery(d["id"], now, now + timedelta(minutes=2)):
            continue
        ch = _resolve_channel(d["channel_key"])
        if ch is None or not ch.get("enabled", 1):
            store.finish_delivery(d["id"], sent=False, error="channel removed or disabled", next_attempt_at=None,
                                  give_up=True)
            continue
        ok, retryable, error = await _send(ch, d["payload"], d["id"])
        attempt = d["attempts"] + 1
        give_up = not ok and (not retryable or attempt >= MAX_ATTEMPTS)
        delay = BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)]
        store.finish_delivery(d["id"], sent=ok, error=error, give_up=give_up,
                              next_attempt_at=None if ok or give_up else utcnow() + timedelta(seconds=delay))
        if ok:
            sent += 1
        else:
            failed += 1
            logger.warning("Warrant Watch notification %s via %s failed (attempt %d): %s%s", d["id"], ch["kind"],
                           attempt, error, " — giving up" if give_up else "")
    return {"sent": sent, "failed": failed}


async def send_test(ch: dict) -> dict:
    payload = {"type": "test", "title": "Warrant Watch test notification",
               "text": "This channel is connected. Security changes for this project will be posted here.",
               "priority": "info", "link": get_settings().public_app_url}
    ok, _, error = await _send(ch, payload, f"test-{uuid.uuid4()}")
    return {"delivered": ok, "error": error}
