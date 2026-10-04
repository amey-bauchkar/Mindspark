"""
Warrant Watch operations: notifications (Slack / Teams / signed webhooks, durable outbox),
access control, lockfile updates and CI sync, triage, deletion, settings, multi-process safety.
All network traffic goes to the offline FakeInternet; webhook endpoints are captured in-process.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sqlite3
from datetime import timedelta

import httpx
import pytest

from app.config import get_settings
from app.providers.cache import load_report
from app.watch import monitor, notify, store
from app.watch.scheduler import WatchScheduler

from tests.test_watch import (  # noqa: F401
    CLIENT, LOCKFILE, NOW, PARSER, analyze, check, enable, env, iso, osv_record,
)

SLACK = "https://hooks.slack.com/services/T000/B000/secretpart"
HOOK = "https://hooks.example.com/warrant"


@pytest.fixture
def inbox(env, monkeypatch):
    """Capture webhook deliveries; `inbox.status` controls the receiver's HTTP answer."""
    class Inbox:
        status = 200
        received: list[httpx.Request] = []

    box = Inbox()
    box.received = []
    real = env.handler

    def handler(request: httpx.Request):
        if request.url.host in ("hooks.slack.com", "hooks.example.com", "acme.webhook.office.com"):
            box.received.append(request)
            return httpx.Response(box.status)
        return real(request)

    env.handler = handler
    monkeypatch.setattr(notify, "verify_safe_outbound_ip", lambda host: True)
    return box


@pytest.fixture
def client(env):
    from fastapi.testclient import TestClient
    import app.main
    with TestClient(app.main.app) as c:
        yield c


def dispatch():
    return asyncio.run(notify.dispatch())


def risky_update_lockfile(parser_version="1.2.0", extra=True) -> str:
    data = json.loads(LOCKFILE)
    pk = data["packages"]
    pk["node_modules/acme-tiny-parser"]["version"] = parser_version
    if extra:
        pk[""]["dependencies"]["acme-new-lib"] = "0.1.0"
        pk["node_modules/acme-new-lib"] = {"version": "0.1.0", "license": "MIT",
                                           "resolved": "https://registry.npmjs.org/acme-new-lib/-/acme-new-lib-0.1.0.tgz"}
    return json.dumps(data)


# ─── Channels ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("kind,url,error", [
    ("webhook", "http://hooks.example.com/x", "https"),
    ("webhook", "https://127.0.0.1/x", "public"),
    ("webhook", "https://10.1.2.3/x", "public"),
    ("webhook", "https://metadata.internal/x", "public"),
    ("webhook", "https://user:pw@hooks.example.com/x", "credentials"),
    ("slack", "https://evil.example.com/services/x", "hooks.slack.com"),
    ("teams", "https://evil.example.com/x", "Teams"),
    ("email", SLACK, "Channel type"),
])
def test_channel_urls_are_validated(kind, url, error):
    with pytest.raises(notify.ChannelError, match=error):
        notify.validate_channel(kind, url, "medium")


def test_channel_urls_are_secret_and_webhooks_signed(env, client):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    created = client.post(f"/api/watch/{wid}/channels", json={"kind": "webhook", "url": HOOK}).json()
    assert created["signing_secret"] and created["url"] == "https://hooks.example.com/…rant"
    detail = client.get(f"/api/watch/{wid}").json()
    assert all("signing_secret" not in c and "secret" not in json.dumps(c).replace("signed", "") for c in detail["channels"])
    assert SLACK not in json.dumps(detail)
    assert client.post(f"/api/watch/{wid}/channels", json={"kind": "slack", "url": "https://x.example.com"}).status_code == 400


# ─── Delivery ─────────────────────────────────────────────────────────────────

def test_security_change_is_delivered_once_per_channel(env, inbox, client):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    client.post(f"/api/watch/{wid}/channels", json={"kind": "slack", "url": SLACK})
    secret = client.post(f"/api/watch/{wid}/channels", json={"kind": "webhook", "url": HOOK}).json()["signing_secret"]
    env.add(osv_record("MAL-2099-5000", "acme-tiny-parser", "1.1.0", fixed=None, malware=True))
    check(wid)
    assert dispatch()["sent"] == 4  # 2 events (package + carried ancestor) × 2 channels
    slack = [r for r in inbox.received if r.url.host == "hooks.slack.com"]
    hook = [r for r in inbox.received if r.url.host == "hooks.example.com"]
    assert len(slack) == 2 and len(hook) == 2
    assert "SECURITY CHANGE DETECTED" in json.loads(slack[0].content)["text"]
    body = hook[0].content
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert hook[0].headers["x-warrant-signature"] == expected
    payload = json.loads(body)
    assert payload["type"] == "security_change" and payload["event"]["current"]["verdict"] == "INCIDENT"
    assert payload["link"].startswith(get_settings().public_app_url)

    # Re-dispatching, re-checking and "restarting" never resend
    check(wid)
    dispatch()
    store.init_watch_db()
    dispatch()
    assert len(inbox.received) == 4
    statuses = {d["status"] for d in store.list_deliveries(wid)}
    assert statuses == {"sent"}


def test_channel_priority_filter(env, inbox, client):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    client.post(f"/api/watch/{wid}/channels", json={"kind": "slack", "url": SLACK, "min_priority": "high"})
    env.add(osv_record("GHSA-test-5001", "acme-dev-runner", "0.9.0", fixed="1.0.0"))  # MONITOR → low priority
    [ev] = check(wid)["events"]
    assert ev["priority"] == "low"
    dispatch()
    assert inbox.received == []


def test_failed_deliveries_are_retried_then_given_up(env, inbox, client):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    client.post(f"/api/watch/{wid}/channels", json={"kind": "webhook", "url": HOOK})
    env.add(osv_record("GHSA-test-5002", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    check(wid)
    inbox.status = 503
    dispatch()
    [d] = store.list_deliveries(wid)
    assert d["status"] == "pending" and d["attempts"] == 1 and d["last_error"] == "HTTP 503"
    dispatch()
    assert len(inbox.received) == 1  # Backoff: not retried immediately
    with sqlite3.connect(get_settings().db_path) as conn:
        conn.execute("UPDATE watch_deliveries SET next_attempt_at = ?", (store.ts(store.utcnow() - timedelta(seconds=1)),))
    inbox.status = 200
    dispatch()
    assert store.list_deliveries(wid)[0]["status"] == "sent" and len(inbox.received) == 2

    env.add(osv_record("GHSA-test-5003", "acme-tiny-parser", "1.1.0", fixed="1.1.1", cves=["CVE-2099-5003"]))
    env.kev.add("CVE-2099-5003")
    check(wid)
    inbox.status = 404  # Misconfigured URL: not retried forever
    dispatch()
    assert any(d["status"] == "failed" and d["last_error"] == "HTTP 404" for d in store.list_deliveries(wid))


def test_events_committed_before_a_crash_are_still_delivered(env, inbox, client, monkeypatch):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    client.post(f"/api/watch/{wid}/channels", json={"kind": "slack", "url": SLACK})
    env.add(osv_record("GHSA-test-5004", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    with monkeypatch.context() as m:
        m.setattr(notify, "queue_events", lambda *a, **k: 0)  # "Crash" before queueing
        assert len(check(wid)["events"]) == 1
    assert store.list_deliveries(wid) == []
    dispatch()  # Reconciliation finds the committed event
    assert len(inbox.received) == 1


def test_unsafe_resolved_address_is_not_contacted(env, inbox, client, monkeypatch):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    client.post(f"/api/watch/{wid}/channels", json={"kind": "webhook", "url": HOOK})
    monkeypatch.setattr(notify, "verify_safe_outbound_ip", lambda host: False)  # DNS rebinding to a private IP
    env.add(osv_record("GHSA-test-5005", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    check(wid)
    dispatch()
    assert inbox.received == [] and "public address" in store.list_deliveries(wid)[0]["last_error"]


def test_monitoring_failure_and_recovery_are_announced_once(env, inbox, client):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    client.post(f"/api/watch/{wid}/channels", json={"kind": "webhook", "url": HOOK, "min_priority": "info"})
    env.down.add("osv")
    for _ in range(4):
        assert check(wid)["check"]["status"] == "failed"
    dispatch()
    kinds = [json.loads(r.content)["type"] for r in inbox.received]
    assert kinds == ["monitoring_failure"]
    assert store.get_watch(wid)["failure_streak"] == 4
    env.down.clear()
    check(wid)
    dispatch()
    assert [json.loads(r.content)["type"] for r in inbox.received] == ["monitoring_failure", "monitoring_recovered"]
    assert store.get_watch(wid)["failure_streak"] == 0


def test_channel_test_endpoint(env, inbox, client):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    cid = client.post(f"/api/watch/{wid}/channels", json={"kind": "teams", "url": "https://acme.webhook.office.com/x"}).json()["id"]
    assert client.post(f"/api/watch/{wid}/channels/{cid}/test").json() == {"delivered": True, "error": None}
    assert json.loads(inbox.received[0].content)["@type"] == "MessageCard"
    assert client.post(f"/api/watch/{wid}/channels/{cid}/delete").json() == {"deleted": cid}


def test_provider_text_cannot_inject_slack_mentions():
    raw, _ = notify.render("slack", {"title": "x <!channel>", "text": "<https://evil|click> & y", "link": None}, None, "d")
    text = json.loads(raw)["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text and "<https://evil" not in text


# ─── Access control ───────────────────────────────────────────────────────────

def test_api_key_and_read_only_key(env, client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "warrant_api_key", "full-key-123")
    monkeypatch.setattr(settings, "warrant_read_key", "read-key-456")
    assert client.get("/api/health").json()["auth_required"] is True
    assert client.get("/api/watch").status_code == 401
    assert client.get("/api/watch", headers={"X-Warrant-Key": "wrong"}).status_code == 401
    assert client.get("/api/watch", headers={"X-Warrant-Key": "read-key-456"}).status_code == 200
    assert client.post("/api/watch/demo", json={}, headers={"X-Warrant-Key": "read-key-456"}).status_code == 403
    assert client.post("/api/analyze", data={"text": LOCKFILE},
                       headers={"Authorization": "Bearer full-key-123"}).status_code == 200
    assert client.options("/api/watch", headers={"Origin": "http://localhost:5173",
                                                 "Access-Control-Request-Method": "GET"}).status_code == 200


def test_api_is_open_without_configured_keys(env, client):
    assert client.get("/api/health").json()["auth_required"] is False
    assert client.get("/api/watch").status_code == 200


# ─── Lockfile updates & CI ────────────────────────────────────────────────────

def test_lockfile_update_reports_introduced_and_removed_risk(env, client):
    env.add(osv_record("GHSA-test-5100", "acme-tiny-parser", "1.1.0", fixed="1.2.0"))
    rid = analyze()
    wid = client.post("/api/watch", json={"report_id": rid}).json()["id"]
    assert store.get_watch(wid)["state"][PARSER]["verdict"] == "UPGRADE"
    env.add(osv_record("MAL-2099-5101", "acme-new-lib", "0.1.0", fixed=None, malware=True))
    env.registry["acme-new-lib"] = env.registry["acme-http-client"]

    res = client.post(f"/api/watch/{wid}/lockfile", data={"text": risky_update_lockfile()})
    assert res.status_code == 200, res.text
    body = res.json()
    kinds = {(e["change_type"], e["package"]) for e in body["events"]}
    assert ("DEPENDENCY_REMOVED", "acme-tiny-parser") in kinds    # The vulnerable version was upgraded away
    assert ("DEPENDENCY_ADDED", "acme-new-lib") in kinds          # A malicious package came in
    added = next(e for e in body["events"] if e["change_type"] == "DEPENDENCY_ADDED")
    assert added["priority"] == "high" and added["current"]["verdict"] == "INCIDENT"
    lock = body["check"]["lockfile"]
    assert lock == {**lock, "added": 2, "removed": 1, "version_changes": 1, "packages": 4}
    w = store.get_watch(wid)
    assert w["package_count"] == 4 and w["latest_report_id"] == body["check"]["report_id"]
    assert w["baseline_report_id"] == rid and load_report(rid) is not None   # History kept
    assert "pkg:npm/acme-tiny-parser@1.2.0" not in w["state"] or w["state"]["pkg:npm/acme-tiny-parser@1.2.0"]["verdict"] != "UPGRADE"
    # Later checks monitor the NEW dependency set
    env.add(osv_record("GHSA-test-5102", "acme-tiny-parser", "1.2.0", fixed="1.3.0"))
    [ev] = check(wid)["events"]
    assert ev["version"] == "1.2.0"
    assert client.post(f"/api/watch/{wid}/lockfile", data={"text": "not json"}).status_code == 400


def test_ci_sync_creates_then_updates_one_project(env, client):
    first = client.post("/api/watch/sync", data={"project": "payments-api", "text": LOCKFILE}).json()
    assert first["created"] is True
    second = client.post("/api/watch/sync", data={"project": "payments-api", "text": risky_update_lockfile(extra=False)}).json()
    assert second["created"] is False and second["watch_id"] == first["watch_id"]
    assert second["check"]["trigger"] == "ci_sync"
    assert len([w for w in store.list_watches() if w["name"] == "payments-api"]) == 1
    assert client.post("/api/watch/sync", data={"project": " ", "text": LOCKFILE}).status_code == 400


# ─── Triage, deletion, settings ───────────────────────────────────────────────

def test_triage_workflow(env, client):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    env.add(osv_record("GHSA-test-5200", "acme-tiny-parser", "1.1.0", fixed="1.1.1"))
    [ev] = check(wid)["events"]
    assert client.get("/api/watch/alerts").json()["unacknowledged"] == 1
    res = client.post(f"/api/watch/{wid}/events/{ev['id']}/triage",
                      json={"state": "accepted_risk", "note": "Not reachable in our usage; revisit Q3"}).json()
    assert res["triage_state"] == "accepted_risk" and res["triage_note"].startswith("Not reachable")
    assert client.get("/api/watch/alerts").json()["unacknowledged"] == 0
    assert client.post(f"/api/watch/{wid}/events/{ev['id']}/triage", json={"state": "ignored"}).status_code == 400
    assert client.post(f"/api/watch/{wid}/events/nope/triage", json={"state": "resolved"}).status_code == 404


def test_delete_project_requires_confirmation_and_cascades(env, client):
    rid = analyze()
    wid = client.post("/api/watch", json={"report_id": rid}).json()["id"]
    client.post(f"/api/watch/{wid}/channels", json={"kind": "webhook", "url": HOOK})
    assert client.post(f"/api/watch/{wid}/delete", json={}).status_code == 400
    assert client.post(f"/api/watch/{wid}/delete", json={"confirm": True}).json() == {"deleted": wid}
    assert client.get(f"/api/watch/{wid}").status_code == 404 and store.list_channels(wid) == []
    with sqlite3.connect(get_settings().db_path) as conn:
        assert conn.execute("SELECT retain FROM reports WHERE id = ?", (rid,)).fetchone()[0] == 0


def test_check_interval_setting(env, client):
    wid = client.post("/api/watch", json={"report_id": analyze()}).json()["id"]
    w = client.post(f"/api/watch/{wid}/settings", json={"interval_minutes": 15, "name": "checkout-web"}).json()
    assert w["interval_seconds"] == 900 and w["name"] == "checkout-web"
    assert store.parse_ts(w["next_check_at"]) <= store.utcnow() + timedelta(minutes=15, seconds=5)
    assert client.post(f"/api/watch/{wid}/settings", json={"interval_minutes": 1}).status_code == 400
    assert client.post(f"/api/watch/{wid}/settings", json={"interval_minutes": None}).json()["interval_seconds"] == 3600


# ─── Scale / operations ───────────────────────────────────────────────────────

def test_two_scheduler_processes_never_run_the_same_check(env):
    w = enable(analyze())
    store.set_status(w["id"], "active", store.ts(NOW - timedelta(minutes=1)))

    async def both():
        return await asyncio.gather(WatchScheduler(tick_seconds=0).tick(), WatchScheduler(tick_seconds=0).tick())

    a, b = asyncio.run(both())
    assert len(a) + len(b) == 1 and len(store.list_checks(w["id"])) == 1


def test_scheduler_checks_projects_in_parallel(env, monkeypatch):
    ids = [enable(analyze())["id"] for _ in range(3)]
    for wid in ids:
        store.set_status(wid, "active", store.ts(NOW - timedelta(minutes=1)))
    running, peak = 0, 0
    real = monitor.run_check

    async def tracked(wid, trigger):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.05)
        try:
            return await real(wid, trigger)
        finally:
            running -= 1

    import app.watch.scheduler as sched
    monkeypatch.setattr(sched, "run_check", tracked)
    assert len(asyncio.run(WatchScheduler(tick_seconds=0).tick())) == 3
    assert peak > 1


def test_watch_health_endpoint(env, client):
    client.post("/api/watch", json={"report_id": analyze()})
    h = client.get("/api/watch/health").json()
    assert h["projects"] == 1 and h["failing_projects"] == [] and "notifications" in h
