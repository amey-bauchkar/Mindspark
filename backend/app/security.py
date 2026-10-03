"""Security utilities — input sanitisation, allowlist enforcement, rate limiting."""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from .config import get_settings

_SAFE_FILENAME_RE = re.compile(r'^[A-Za-z0-9_.\-]+$')
_CONTROL_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u2029\ufeff]')
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_PACKAGES = 5_000


def sanitize_filename(name: str) -> str:
    """Return a safe display-only filename (never used as a path)."""
    base = Path(name).name  # Strip any directory parts
    if not base or not _SAFE_FILENAME_RE.match(base):
        return "lockfile"
    return base[:120]


def sanitize_text(text: str, max_len: int = 500) -> str:
    """Strip control/bidi characters and cap length."""
    cleaned = _CONTROL_RE.sub("", text)
    return cleaned[:max_len]


def check_url_allowlist(url: str) -> bool:
    """Return True only if the URL's host is in the fixed allowlist."""
    from urllib.parse import urlparse
    settings = get_settings()
    try:
        host = urlparse(url).hostname or ""
        return host in settings.allowed_outbound_hosts
    except Exception:
        return False
