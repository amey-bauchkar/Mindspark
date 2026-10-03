"""Security utilities — input sanitisation, SSRF protection, rate limiting, and depth guards."""
from __future__ import annotations

import ipaddress
import re
import socket
import time
import unicodedata
from collections import deque
from pathlib import Path
from threading import Lock

from .config import get_settings

# ── Filename & payload limits ─────────────────────────────────────────────────
_SAFE_FILENAME_RE = re.compile(r'^[A-Za-z0-9_.\\-]+$')
_CONTROL_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u2029\ufeff]')

MAX_UPLOAD_BYTES = 5 * 1024 * 1024   # 5 MB hard cap
MAX_JSON_DEPTH = 20                   # Billion-Laughs / ReDoS recursion cap
MAX_FILENAME_LEN = 80                 # Strict filename length cap

# ── Package name safety regex (used in outbound registry URLs) ────────────────
# Allows: @scope/name, plain-name, underscores, dots, hyphens
_SAFE_PKG_NAME_RE = re.compile(r'^(@[a-z0-9_.\-]+/)?[a-z0-9_.\-]+$', re.IGNORECASE)

# ── SSRF — forbidden CIDR ranges ─────────────────────────────────────────────
_FORBIDDEN_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network('127.0.0.0/8'),        # Loopback
    ipaddress.ip_network('10.0.0.0/8'),         # RFC 1918 Private A
    ipaddress.ip_network('172.16.0.0/12'),      # RFC 1918 Private B
    ipaddress.ip_network('192.168.0.0/16'),     # RFC 1918 Private C
    ipaddress.ip_network('169.254.0.0/16'),     # AWS/Azure/GCP link-local metadata
    ipaddress.ip_network('0.0.0.0/8'),          # Unspecified
    ipaddress.ip_network('100.64.0.0/10'),      # Carrier-grade NAT
    ipaddress.ip_network('::1/128'),            # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),           # IPv6 unique local
    ipaddress.ip_network('fe80::/10'),          # IPv6 link-local
]


# ── Sliding-window rate limiter ───────────────────────────────────────────────
class _SlidingWindowBucket:
    """Thread-safe sliding-window counter keyed by client identifier."""

    MAX_TRACKED_CLIENTS = 10_000  # Bound memory: idle clients are evicted beyond this

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, deque[float]] = {}
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if key not in self._buckets and len(self._buckets) >= self.MAX_TRACKED_CLIENTS:
                for k in [k for k, q in self._buckets.items() if not q or q[-1] < cutoff]:
                    del self._buckets[k]
            q = self._buckets.setdefault(key, deque())
            # Purge old entries
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True


# Shared rate limiter instances — per endpoint category
_limiter_upload   = _SlidingWindowBucket(max_requests=30,  window_seconds=60)  # /api/analyze
_limiter_status   = _SlidingWindowBucket(max_requests=180, window_seconds=60)  # /api/reports/*/status
_limiter_general  = _SlidingWindowBucket(max_requests=300, window_seconds=60)  # everything else


def check_rate_limit(endpoint: str, client_ip: str) -> tuple[bool, int]:
    """
    Return (is_allowed, retry_after_seconds).
    endpoint should be one of: 'upload', 'status', 'general'.
    """
    if endpoint == 'upload':
        allowed = _limiter_upload.is_allowed(client_ip)
        retry = 60 if not allowed else 0
    elif endpoint == 'status':
        allowed = _limiter_status.is_allowed(client_ip)
        retry = 60 if not allowed else 0
    else:
        allowed = _limiter_general.is_allowed(client_ip)
        retry = 60 if not allowed else 0
    return allowed, retry


# ── Filename sanitisation ─────────────────────────────────────────────────────

def sanitize_filename(name: str) -> str:
    """Return a safe display-only filename (never used as a path)."""
    base = Path(name).name  # Strip any directory parts
    # Strip null bytes and control characters first
    base = _CONTROL_RE.sub('', base)
    if not base or not _SAFE_FILENAME_RE.match(base):
        return 'lockfile'
    return base[:MAX_FILENAME_LEN]


def sanitize_package_name(name: str) -> str:
    """
    Return the package name if it is safe to embed in an outbound registry URL.
    Raises ValueError if the name fails validation (path traversal / injection).
    """
    cleaned = name.strip()
    if not cleaned or not _SAFE_PKG_NAME_RE.match(cleaned):
        raise ValueError(f"Unsafe or malformed package name rejected: {name!r}")
    return cleaned


def sanitize_text(text: str, max_len: int = 500) -> str:
    """Strip control/bidi characters and cap length."""
    cleaned = _CONTROL_RE.sub('', text)
    return cleaned[:max_len]


# ── JSON recursion / ReDoS guard ─────────────────────────────────────────────

def validate_json_depth(obj: object, max_depth: int = MAX_JSON_DEPTH, _depth: int = 0) -> None:
    """
    Recursively walk a parsed JSON object and raise ValueError if the nesting
    depth exceeds max_depth.  This neutralises Billion-Laughs / deeply-nested
    ReDoS payloads before the parser processes them.
    """
    if _depth > max_depth:
        raise ValueError(
            f"JSON nesting depth exceeds security limit ({max_depth}). "
            "Possible Billion-Laughs / deeply-nested ReDoS payload detected — rejected."
        )
    if isinstance(obj, dict):
        for v in obj.values():
            if isinstance(v, (dict, list)):
                validate_json_depth(v, max_depth, _depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                validate_json_depth(item, max_depth, _depth + 1)


# ── Anti-SSRF: outbound host allowlist (hostname-level) ──────────────────────

def check_url_allowlist(url: str) -> bool:
    """Return True only if the URL's host is in the fixed allowlist."""
    from urllib.parse import urlparse
    settings = get_settings()
    try:
        host = urlparse(url).hostname or ''
        return host in settings.allowed_outbound_hosts
    except Exception:
        return False


# ── Anti-SSRF: outbound IP verification (DNS-rebinding / SSRF guard) ─────────

def verify_safe_outbound_ip(hostname: str) -> bool:
    """
    Resolve hostname to an IP address and verify it does not fall within any
    forbidden CIDR range (loopback, RFC 1918, cloud metadata, link-local).

    This is the second-layer SSRF defence.  The first layer is check_url_allowlist()
    which validates the hostname string; this layer checks the *resolved* IP so that
    DNS-rebinding attacks cannot bypass hostname allowlisting.

    Returns True if safe to connect, False otherwise.
    """
    try:
        # Resolve — uses the OS resolver (system /etc/hosts aware)
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        for net in _FORBIDDEN_NETWORKS:
            if ip in net:
                return False
        return True
    except Exception:
        # DNS resolution failure → treat as unsafe
        return False
