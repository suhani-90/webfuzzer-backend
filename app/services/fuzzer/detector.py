"""
app/services/fuzzer/detector.py
─────────────────────────────────
Vulnerability detection rules engine.
Analyses HTTP responses for signatures of:
  - SQL Injection (error-based, time-based, boolean)
  - Cross-Site Scripting (reflected)
  - Remote Code Execution (command output)
  - Authentication Bypass (unexpected access)
"""

import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from app.core.logging import get_logger
from app.models.vulnerability import Severity

logger = get_logger(__name__)


@dataclass
class DetectionResult:
    """Result of running detection rules against a single HTTP response."""

    is_vulnerable: bool = False
    vuln_type: Optional[str] = None
    severity: Optional[str] = None
    evidence: Optional[str] = None  # relevant snippet from response body
    confidence: float = 0.0  # 0.0 – 1.0


# ── SQL Injection Signatures ───────────────────────────────────────────────────
SQLI_ERROR_PATTERNS = [
    # MySQL
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"mysql_fetch_array\(\)", re.I),
    re.compile(r"ORA-\d{5}:", re.I),  # Oracle
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"ODBC Microsoft Access Driver", re.I),
    re.compile(r"SQLite\.Exception", re.I),
    re.compile(r"PG::SyntaxError", re.I),  # PostgreSQL
    re.compile(r"supplied argument is not a valid MySQL result", re.I),
    re.compile(r"Column count doesn't match value count", re.I),
    re.compile(r"Table .* doesn't exist", re.I),
    re.compile(r"ERROR:\s+syntax error at or near", re.I),
]

# Patterns suggesting DB data was leaked (UNION-based)
SQLI_DATA_LEAK_PATTERNS = [
    re.compile(r"\b(root|admin|administrator)\b.{0,30}\b(password|passwd|pwd)\b", re.I),
    re.compile(r"information_schema", re.I),
    re.compile(r"@@version", re.I),
]


# ── XSS Signatures ─────────────────────────────────────────────────────────────
def _xss_reflected_pattern(payload: str) -> re.Pattern:
    """Build a regex to detect if the payload is reflected in the response."""
    escaped = re.escape(payload)
    return re.compile(escaped[:50], re.I)  # match first 50 chars of payload


# ── RCE Signatures ─────────────────────────────────────────────────────────────
RCE_PATTERNS = [
    re.compile(r"root:x:0:0:", re.I),  # /etc/passwd
    re.compile(r"\[boot loader\]", re.I),  # win.ini
    re.compile(r"(uid=\d+\([\w]+\)\s+gid=\d+)", re.I),  # id command output
    re.compile(r"Windows IP Configuration", re.I),  # ipconfig
    re.compile(r"inet addr:", re.I),  # ifconfig
    re.compile(r"PHP Fatal error:", re.I),
    re.compile(r"sh: .+: command not found", re.I),
]

# ── Auth Bypass Signatures ──────────────────────────────────────────────────────
AUTH_BYPASS_INDICATORS = [
    "admin panel",
    "dashboard",
    "welcome, admin",
    "logged in as admin",
    "access granted",
    "privileged",
]


class VulnerabilityDetector:
    """
    Stateless detection engine.
    Each detect_* method inspects a response body/status and returns a DetectionResult.
    """

    def analyse(
        self,
        url: str,
        payload: str,
        category: str,
        status_code: int,
        response_body: str,
        response_time_ms: float,
        baseline_time_ms: float = 100.0,
    ) -> DetectionResult:
        """
        Run appropriate detection rules based on payload category.

        Args:
            url: The URL that was fuzzed.
            payload: The injected payload string.
            category: Payload category (sqli | xss | rce | auth_bypass | ...).
            status_code: HTTP response status code.
            response_body: Full HTTP response body as string.
            response_time_ms: Time taken for this request in milliseconds.
            baseline_time_ms: Average response time without injection (for timing attacks).

        Returns:
            DetectionResult with vuln details if detected.
        """
        if category == "sqli":
            return self._detect_sqli(
                payload, response_body, response_time_ms, baseline_time_ms
            )
        elif category == "xss":
            return self._detect_xss(payload, response_body)
        elif category == "rce":
            return self._detect_rce(payload, response_body)
        elif category == "auth_bypass":
            return self._detect_auth_bypass(payload, status_code, response_body)
        else:
            return self._detect_generic_anomaly(
                status_code, response_body, baseline_time_ms, response_time_ms
            )

    def _detect_sqli(
        self,
        payload: str,
        body: str,
        response_time_ms: float,
        baseline_ms: float,
    ) -> DetectionResult:
        """Detect SQL injection via error messages, data leaks, or time delays."""
        body_lower = body[:5000]  # Only inspect first 5KB for performance

        # Error-based detection
        for pattern in SQLI_ERROR_PATTERNS:
            match = pattern.search(body_lower)
            if match:
                snippet = body_lower[max(0, match.start() - 50) : match.end() + 100]
                return DetectionResult(
                    is_vulnerable=True,
                    vuln_type="SQL Injection",
                    severity=Severity.HIGH.value,
                    evidence=snippet.strip(),
                    confidence=0.95,
                )

        # Data leak detection (UNION-based)
        for pattern in SQLI_DATA_LEAK_PATTERNS:
            if pattern.search(body_lower):
                return DetectionResult(
                    is_vulnerable=True,
                    vuln_type="SQL Injection",
                    severity=Severity.HIGH.value,
                    evidence="Sensitive database data detected in response.",
                    confidence=0.85,
                )

        # Time-based blind SQLi (>3x baseline indicates delay injection)
        if response_time_ms > max(baseline_ms * 3, 3000):
            return DetectionResult(
                is_vulnerable=True,
                vuln_type="SQL Injection",
                severity=Severity.HIGH.value,
                evidence=f"Response delayed {response_time_ms:.0f}ms vs baseline {baseline_ms:.0f}ms",
                confidence=0.75,
            )

        return DetectionResult()

    def _detect_xss(self, payload: str, body: str) -> DetectionResult:
        """Detect reflected XSS by checking if payload appears in response body."""
        # Look for reflected payload (unencoded)
        pattern = _xss_reflected_pattern(payload)
        if pattern.search(body):
            return DetectionResult(
                is_vulnerable=True,
                vuln_type="Cross-Site Scripting",
                severity=Severity.HIGH.value,
                evidence=f"Payload reflected in response: {payload[:80]}",
                confidence=0.90,
            )

        # Check for partially encoded reflection
        encoded_checks = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace('"', "&quot;"),
        ]
        for encoded in encoded_checks:
            if re.search(re.escape(encoded[:40]), body, re.I):
                return DetectionResult(
                    is_vulnerable=True,
                    vuln_type="Cross-Site Scripting",
                    severity=Severity.MEDIUM.value,
                    evidence=f"Encoded payload reflected: {encoded[:80]}",
                    confidence=0.70,
                )

        return DetectionResult()

    def _detect_rce(self, payload: str, body: str) -> DetectionResult:
        """Detect RCE by scanning response for command output signatures."""
        for pattern in RCE_PATTERNS:
            match = pattern.search(body)
            if match:
                snippet = body[max(0, match.start() - 20) : match.end() + 100]
                return DetectionResult(
                    is_vulnerable=True,
                    vuln_type="Remote Code Execution",
                    severity=Severity.HIGH.value,
                    evidence=snippet.strip(),
                    confidence=0.95,
                )
        return DetectionResult()

    def _detect_auth_bypass(
        self, payload: str, status_code: int, body: str
    ) -> DetectionResult:
        """Detect auth bypass via unexpected 200 responses or admin content."""
        body_lower = body.lower()
        for indicator in AUTH_BYPASS_INDICATORS:
            if indicator in body_lower:
                return DetectionResult(
                    is_vulnerable=True,
                    vuln_type="Broken Auth",
                    severity=Severity.HIGH.value,
                    evidence=f"Admin content detected: '{indicator}'",
                    confidence=0.80,
                )
        return DetectionResult()

    def _detect_generic_anomaly(
        self,
        status_code: int,
        body: str,
        baseline_ms: float,
        response_time_ms: float,
    ) -> DetectionResult:
        """Generic anomaly detection for uncategorised payloads."""
        # 500 errors often signal backend crashes from injection
        if status_code >= 500:
            return DetectionResult(
                is_vulnerable=True,
                vuln_type="Server Error (Potential Injection)",
                severity=Severity.MEDIUM.value,
                evidence=f"HTTP {status_code} returned — possible injection crash",
                confidence=0.60,
            )
        # Significant timing anomaly
        if response_time_ms > baseline_ms * 4:
            return DetectionResult(
                is_vulnerable=True,
                vuln_type="Timing Anomaly",
                severity=Severity.LOW.value,
                evidence=f"Response time {response_time_ms:.0f}ms vs baseline {baseline_ms:.0f}ms",
                confidence=0.55,
            )
        return DetectionResult()


# Module-level singleton
detector = VulnerabilityDetector()
