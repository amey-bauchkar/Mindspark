"""
Phase 6 Security Regression Suite — Enterprise Hardening Tests
Tests for: ReDoS depth guard, private IP SSRF blocking, package name sanitizer, rate limiter.
"""
from __future__ import annotations
import pytest


class TestJsonDepthGuard:
    """Phase 1 -- Billion-Laughs / ReDoS JSON recursion cap."""

    def test_normal_depth_passes(self):
        """Normal lockfile JSON (depth ~2) must pass cleanly."""
        from app.security import validate_json_depth
        obj = {"packages": {"node_modules/a": {"version": "1.0.0", "deps": {"b": "1.0.0"}}}}
        validate_json_depth(obj)  # Must not raise

    def test_max_depth_rejected(self):
        """A JSON structure exceeding MAX_JSON_DEPTH must raise ValueError."""
        from app.security import validate_json_depth, MAX_JSON_DEPTH
        nested: dict = {}
        current = nested
        for _ in range(MAX_JSON_DEPTH + 5):
            child: dict = {}
            current["x"] = child
            current = child
        with pytest.raises(ValueError, match="depth"):
            validate_json_depth(nested)

    def test_flat_large_object_passes(self):
        """A flat dict with many keys (not deep) must pass."""
        from app.security import validate_json_depth
        flat = {str(i): f"value-{i}" for i in range(5000)}
        validate_json_depth(flat)  # Must not raise

    def test_billion_laughs_list_rejected(self):
        """Deeply nested list (Billion Laughs list variant) must be rejected."""
        from app.security import validate_json_depth, MAX_JSON_DEPTH
        node: list = []
        current: list = node
        for _ in range(MAX_JSON_DEPTH + 3):
            child: list = []
            current.append(child)
            current = child
        with pytest.raises(ValueError, match="depth"):
            validate_json_depth(node)


class TestAntiSSRFGuard:
    """Phase 2 -- SSRF / DNS-rebinding / private IP filter."""

    def test_loopback_is_forbidden(self):
        """127.0.0.1 (loopback) must be classified as forbidden."""
        import ipaddress
        from app.security import _FORBIDDEN_NETWORKS
        ip = ipaddress.ip_address("127.0.0.1")
        assert any(ip in net for net in _FORBIDDEN_NETWORKS)

    def test_rfc1918_10_is_forbidden(self):
        """10.x.x.x RFC 1918 addresses must be forbidden."""
        import ipaddress
        from app.security import _FORBIDDEN_NETWORKS
        ip = ipaddress.ip_address("10.0.0.1")
        assert any(ip in net for net in _FORBIDDEN_NETWORKS)

    def test_rfc1918_172_is_forbidden(self):
        """172.16.x.x addresses must be forbidden."""
        import ipaddress
        from app.security import _FORBIDDEN_NETWORKS
        ip = ipaddress.ip_address("172.16.0.1")
        assert any(ip in net for net in _FORBIDDEN_NETWORKS)

    def test_rfc1918_192168_is_forbidden(self):
        """192.168.x.x must be forbidden."""
        import ipaddress
        from app.security import _FORBIDDEN_NETWORKS
        ip = ipaddress.ip_address("192.168.1.1")
        assert any(ip in net for net in _FORBIDDEN_NETWORKS)

    def test_aws_metadata_endpoint_is_forbidden(self):
        """169.254.169.254 (AWS/Azure/GCP metadata) must be forbidden."""
        import ipaddress
        from app.security import _FORBIDDEN_NETWORKS
        ip = ipaddress.ip_address("169.254.169.254")
        assert any(ip in net for net in _FORBIDDEN_NETWORKS)

    def test_public_ip_is_allowed(self):
        """A standard public IP must NOT appear in the forbidden set."""
        import ipaddress
        from app.security import _FORBIDDEN_NETWORKS
        ip = ipaddress.ip_address("1.1.1.1")  # Cloudflare DNS -- public
        assert not any(ip in net for net in _FORBIDDEN_NETWORKS)


class TestPackageNameSanitizer:
    """Phase 2 -- URL injection / path traversal protection in registry queries."""

    def test_valid_scoped_package_passes(self):
        from app.security import sanitize_package_name
        assert sanitize_package_name("@babel/core") == "@babel/core"

    def test_valid_plain_package_passes(self):
        from app.security import sanitize_package_name
        assert sanitize_package_name("lodash") == "lodash"

    def test_path_traversal_rejected(self):
        from app.security import sanitize_package_name
        with pytest.raises(ValueError):
            sanitize_package_name("../../etc/passwd")

    def test_null_byte_injection_rejected(self):
        from app.security import sanitize_package_name
        with pytest.raises(ValueError):
            sanitize_package_name("lodash\x00malicious")

    def test_empty_name_rejected(self):
        from app.security import sanitize_package_name
        with pytest.raises(ValueError):
            sanitize_package_name("")

    def test_command_injection_rejected(self):
        from app.security import sanitize_package_name
        with pytest.raises(ValueError):
            sanitize_package_name("lodash; rm -rf /")


class TestRateLimiter:
    """Phase 3 -- Sliding-window rate limiter logic."""

    def test_allows_within_limit(self):
        from app.security import _SlidingWindowBucket
        bucket = _SlidingWindowBucket(max_requests=5, window_seconds=60)
        results = [bucket.is_allowed("test-ip-a") for _ in range(5)]
        assert all(results)

    def test_blocks_over_limit(self):
        from app.security import _SlidingWindowBucket
        bucket = _SlidingWindowBucket(max_requests=3, window_seconds=60)
        for _ in range(3):
            bucket.is_allowed("test-ip-b")
        assert not bucket.is_allowed("test-ip-b")

    def test_different_ips_are_isolated(self):
        from app.security import _SlidingWindowBucket
        bucket = _SlidingWindowBucket(max_requests=2, window_seconds=60)
        bucket.is_allowed("ip-c")
        bucket.is_allowed("ip-c")
        # ip-c exhausted, ip-d should still be allowed
        assert bucket.is_allowed("ip-d")
        assert not bucket.is_allowed("ip-c")

    def test_check_rate_limit_returns_tuple(self):
        from app.security import check_rate_limit
        allowed, retry_after = check_rate_limit("upload", "5.6.7.8")
        assert isinstance(allowed, bool)
        assert isinstance(retry_after, int)
