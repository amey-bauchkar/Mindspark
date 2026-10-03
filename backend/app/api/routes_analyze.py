"""Analysis routes — POST /api/analyze, POST /api/analyze/sample/{id}"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile

from ..jobs import run_analysis, get_progress
from ..security import sanitize_filename, MAX_UPLOAD_BYTES

router = APIRouter(prefix="/api")

SAMPLES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "samples"
SAMPLE_IDS = {
    "legacy-express": "legacy-express",
    "axios-replay": "axios-replay",
    "python-requirements": "python-requirements",
}


@router.post("/analyze")
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
    context: str = Form(default="{}"),
):
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
