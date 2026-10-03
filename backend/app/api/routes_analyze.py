"""Analysis routes — POST /api/analyze, POST /api/analyze/sample/{id}"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Request, UploadFile

from ..jobs import run_analysis, get_progress
from ..security import (
    sanitize_filename,
    validate_json_depth,
    check_rate_limit,
    MAX_UPLOAD_BYTES,
)

router = APIRouter(prefix="/api")

SAMPLES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "samples"
SAMPLE_IDS = {
    "slack-action": "slack-action",
    "legacy-express": "legacy-express",
    "axios-replay": "axios-replay",
    "python-requirements": "python-requirements",
}


@router.post("/analyze")
async def analyze(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
    context: str = Form(default="{}"),
):
    # ── Rate limiting ─────────────────────────────────────────────────────────
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = check_rate_limit('upload', client_ip)
    if not allowed:
        raise HTTPException(
            429,
            "Too many analysis requests. Please wait before submitting again.",
            headers={"Retry-After": str(retry_after)},
        )

    content = None
    filename = "lockfile"

    if file:
        raw = await file.read()
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "File too large (max 5 MB)")
        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            raise HTTPException(400, "Could not decode file as UTF-8")
        filename = sanitize_filename(file.filename or "lockfile")
    elif text:
        if len(text) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "Content too large (max 5 MB)")
        content = text
    else:
        raise HTTPException(400, "Provide a file or text content")

    # ── JSON Depth Guard (Billion-Laughs / ReDoS defence) ────────────────────
    if content:
        try:
            parsed_raw = json.loads(content)
            validate_json_depth(parsed_raw)
        except ValueError as e:
            err_msg = str(e)
            if "depth" in err_msg.lower():
                raise HTTPException(400, f"Rejected: {err_msg}")
            # Plain JSON parse error will be re-raised by the engine gracefully
        except Exception:
            pass  # Non-JSON files (requirements.txt) are handled downstream

    try:
        context_data = json.loads(context)
    except Exception:
        context_data = {}

    report_id = str(uuid.uuid4())
    background_tasks.add_task(run_analysis, report_id, content, filename, context_data)
    return {"report_id": report_id}


def _load_sample_content(sample_id: str) -> tuple[str, str]:
    if sample_id not in SAMPLE_IDS:
        raise HTTPException(404, f"Sample '{sample_id}' not found. Available: {list(SAMPLE_IDS.keys())}")

    sample_dir = SAMPLES_DIR / sample_id
    for fname in ("package-lock.json", "requirements.txt"):
        fpath = sample_dir / fname
        if fpath.exists():
            return fpath.read_text(encoding="utf-8"), fname

    raise HTTPException(404, f"No lockfile found for sample '{sample_id}'")


@router.post("/analyze/sample")
async def analyze_sample_json(
    body: dict,
    background_tasks: BackgroundTasks,
):
    sample_id = body.get("sample_id", "")
    content, filename = _load_sample_content(sample_id)
    context_data = body.get("context", {})
    if isinstance(context_data, str):
        try:
            context_data = json.loads(context_data)
        except Exception:
            context_data = {}

    report_id = str(uuid.uuid4())
    background_tasks.add_task(run_analysis, report_id, content, filename, context_data)
    return {"report_id": report_id}


@router.post("/analyze/sample/{sample_id}")
async def analyze_sample_path(
    sample_id: str,
    background_tasks: BackgroundTasks,
    context: str = Form(default="{}"),
):
    content, filename = _load_sample_content(sample_id)
    try:
        context_data = json.loads(context)
    except Exception:
        context_data = {}

    report_id = str(uuid.uuid4())
    background_tasks.add_task(run_analysis, report_id, content, filename, context_data)
    return {"report_id": report_id}
