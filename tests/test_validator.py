"""
tests/test_validator.py
────────────────────────
Unit tests for the URL validator (SSRF prevention).
"""

import pytest
from app.utils.url_validator import URLValidator


@pytest.fixture
def validator():
    return URLValidator()


def test_valid_public_url(validator):
    valid, reason = validator.validate("https://example.com/api")
    assert valid, reason


def test_localhost_blocked(validator):
    valid, reason = validator.validate("http://localhost:8080/admin")
    assert not valid
    assert "not permitted" in reason.lower()


def test_private_ip_blocked(validator):
    valid, reason = validator.validate("http://192.168.1.1/")
    assert not valid


def test_loopback_blocked(validator):
    valid, reason = validator.validate("http://127.0.0.1/secret")
    assert not valid


def test_ftp_scheme_blocked(validator):
    valid, reason = validator.validate("ftp://example.com/file")
    assert not valid
    assert "scheme" in reason.lower()


def test_empty_url(validator):
    valid, reason = validator.validate("")
    assert not valid


def test_no_scheme(validator):
    valid, reason = validator.validate("example.com/api")
    assert not valid


def test_dangerous_port_blocked(validator):
    valid, reason = validator.validate("http://example.com:6379/")
    assert not valid
    assert "port" in reason.lower()


def test_sanitise_strips_fragment(validator):
    result = validator.sanitise("https://example.com/api#section")
    assert "#section" not in result


def test_sanitise_strips_trailing_slash(validator):
    result = validator.sanitise("https://example.com/api/")
    assert not result.endswith("/")


"""
tests/test_detector.py
───────────────────────
Unit tests for the vulnerability detection engine.
"""

from app.services.fuzzer.detector import VulnerabilityDetector


def test_sqli_error_detected():
    det = VulnerabilityDetector()
    result = det.analyse(
        url="http://example.com/users?id=1",
        payload="' OR '1'='1",
        category="sqli",
        status_code=500,
        response_body="You have an error in your SQL syntax near '1'='1'",
        response_time_ms=120.0,
        baseline_time_ms=100.0,
    )
    assert result.is_vulnerable
    assert result.vuln_type == "SQL Injection"
    assert result.severity == "High"


def test_sqli_time_based_detected():
    det = VulnerabilityDetector()
    result = det.analyse(
        url="http://example.com/",
        payload="'; SLEEP(5)--",
        category="sqli",
        status_code=200,
        response_body="Normal response",
        response_time_ms=6000.0,  # 6s vs 100ms baseline
        baseline_time_ms=100.0,
    )
    assert result.is_vulnerable
    assert "time" in result.evidence.lower() or "delay" in result.evidence.lower()


def test_xss_reflected_detected():
    det = VulnerabilityDetector()
    payload = "<script>alert(1)</script>"
    result = det.analyse(
        url="http://example.com/search?q=",
        payload=payload,
        category="xss",
        status_code=200,
        response_body=f"<div>Results for: {payload}</div>",
        response_time_ms=80.0,
        baseline_time_ms=80.0,
    )
    assert result.is_vulnerable
    assert result.vuln_type == "Cross-Site Scripting"


def test_no_vuln_clean_response():
    det = VulnerabilityDetector()
    result = det.analyse(
        url="http://example.com/",
        payload="test",
        category="sqli",
        status_code=200,
        response_body="<html><body>Welcome</body></html>",
        response_time_ms=100.0,
        baseline_time_ms=100.0,
    )
    assert not result.is_vulnerable


def test_rce_detected():
    det = VulnerabilityDetector()
    result = det.analyse(
        url="http://example.com/exec",
        payload="$(id)",
        category="rce",
        status_code=200,
        response_body="uid=1000(www-data) gid=1000(www-data)",
        response_time_ms=200.0,
        baseline_time_ms=100.0,
    )
    assert result.is_vulnerable
    assert result.vuln_type == "Remote Code Execution"
