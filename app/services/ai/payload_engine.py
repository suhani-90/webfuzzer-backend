"""
app/services/ai/payload_engine.py
──────────────────────────────────
Combines Gemini AI + static payload libraries to produce
a rich, categorised, deduplicated set of fuzzing payloads.
"""

from typing import Dict, List, Optional

from app.core.logging import get_logger
from app.services.ai.gemini_client import gemini_client
from app.services.fuzzer.payloads.sqli import SQLI_PAYLOADS
from app.services.fuzzer.payloads.xss import XSS_PAYLOADS
from app.services.fuzzer.payloads.rce import RCE_PAYLOADS
from app.services.fuzzer.payloads.auth_bypass import AUTH_BYPASS_PAYLOADS

logger = get_logger(__name__)

# Category constants
CAT_SQLI = "sqli"
CAT_XSS = "xss"
CAT_RCE = "rce"
CAT_AUTH = "auth_bypass"
CAT_OVERFLOW = "overflow"
CAT_SPECIAL = "special_char"


class PayloadEngine:
    """
    Orchestrates payload generation from two sources:
    1. Static libraries (always available, fast)
    2. Gemini AI (context-aware, generated per scan)

    Deduplicates and categorises all payloads before returning.
    """

    async def generate(
        self,
        target_url: str,
        scan_type: str,
        include_sql: bool = True,
        include_xss: bool = True,
        include_rce: bool = False,
        include_auth: bool = False,
        include_overflow: bool = False,
        include_special: bool = False,
        custom_context: str = "",
        ai_count: int = 25,
    ) -> Dict[str, List[str]]:
        """
        Generate a categorised payload dictionary for a scan.

        Returns:
            Dict mapping category name → list of payload strings.
        """
        categorised: Dict[str, List[str]] = {}

        # 1. Pull static payloads based on config
        if include_sql:
            categorised[CAT_SQLI] = list(SQLI_PAYLOADS)
        if include_xss:
            categorised[CAT_XSS] = list(XSS_PAYLOADS)
        if include_rce:
            categorised[CAT_RCE] = list(RCE_PAYLOADS)
        if include_auth:
            categorised[CAT_AUTH] = list(AUTH_BYPASS_PAYLOADS)
        if include_overflow:
            categorised[CAT_OVERFLOW] = self._overflow_payloads()
        if include_special:
            categorised[CAT_SPECIAL] = self._special_char_payloads()

        # 2. Generate AI payloads (runs concurrently)
        ai_payloads = await self._generate_ai_payloads(
            target_url=target_url,
            scan_type=scan_type,
            custom_context=custom_context,
            count=ai_count,
            include_sql=include_sql,
            include_xss=include_xss,
        )

        # 3. Merge AI payloads into appropriate categories
        for category, payloads in ai_payloads.items():
            if category in categorised:
                categorised[category].extend(payloads)
            else:
                categorised[category] = payloads

        # 4. Deduplicate within each category
        for category in categorised:
            seen = set()
            deduped = []
            for p in categorised[category]:
                if p not in seen and p.strip():
                    seen.add(p)
                    deduped.append(p)
            categorised[category] = deduped

        total = sum(len(v) for v in categorised.values())
        logger.info(
            "payload_engine.generated",
            total=total,
            categories=list(categorised.keys()),
            target=target_url,
        )
        return categorised

    async def _generate_ai_payloads(
        self,
        target_url: str,
        scan_type: str,
        custom_context: str,
        count: int,
        include_sql: bool,
        include_xss: bool,
    ) -> Dict[str, List[str]]:
        """
        Call Gemini to generate context-aware payloads.
        Falls back to empty dict if AI is unavailable.
        """
        # Build a targeted prompt based on scan parameters
        categories_requested = []
        if include_sql:
            categories_requested.append("sqli")
        if include_xss:
            categories_requested.append("xss")

        prompt = f"""
You are performing authorized security testing on: {target_url}
Scan type: {scan_type}
{"Additional context: " + custom_context if custom_context else ""}

Generate {count} advanced fuzzing payloads for the following categories: {', '.join(categories_requested)}.

Requirements:
- Focus on modern, evasion-aware payloads
- Include both classic and obfuscated variants
- Make payloads specific to the URL pattern if possible

Return a JSON object with this exact structure:
{{
  "sqli": ["payload1", "payload2", ...],
  "xss": ["payload1", "payload2", ...]
}}

Only include keys for categories that were requested.
"""
        result = await gemini_client.generate_json(prompt)

        if not isinstance(result, dict):
            logger.warning("ai_payload_engine.invalid_response", result=result)
            return {}

        # Validate: ensure values are lists of strings
        validated = {}
        for key, value in result.items():
            if isinstance(value, list):
                validated[key] = [str(p) for p in value if p]

        logger.info("ai_payload_engine.success", categories=list(validated.keys()))
        return validated

    async def generate_remediation(
        self, vuln_type: str, url: str, parameter: str, payload: str
    ) -> str:
        """
        Ask Gemini to generate a specific remediation recommendation
        for a detected vulnerability.
        """
        prompt = f"""
A {vuln_type} vulnerability was detected in an authorized penetration test.

Details:
- URL: {url}
- Vulnerable parameter: {parameter}
- Attack payload that triggered it: {payload}

Provide a concise, developer-focused remediation guide (3-5 sentences).
Be specific and actionable. Output plain text, no markdown.
"""
        response = await gemini_client.generate_text(prompt)
        if response:
            return response.strip()

        # Fallback static recommendation
        return self._static_remediation(vuln_type)

    async def generate_executive_summary(
        self, target_url: str, vuln_count: int, severity_breakdown: dict
    ) -> str:
        """Generate an executive summary paragraph for the report."""
        prompt = f"""
Write a 3-sentence executive summary for a security audit report.

Target: {target_url}
Total vulnerabilities found: {vuln_count}
Severity breakdown: {severity_breakdown}

Write in a professional, concise tone suitable for a security report.
Output plain text only, no markdown or bullet points.
"""
        response = await gemini_client.generate_text(prompt)
        if response:
            return response.strip()
        return (
            f"Security assessment of {target_url} identified {vuln_count} vulnerabilities "
            "requiring remediation. Immediate attention is recommended for all high-severity findings. "
            "A full remediation plan should be implemented before the next production deployment."
        )

    def _overflow_payloads(self) -> List[str]:
        """Long string buffer overflow payloads."""
        return [
            "A" * 1000,
            "A" * 5000,
            "A" * 10000,
            "%s" * 100,
            "{{" * 50 + "}}" * 50,
        ]

    def _special_char_payloads(self) -> List[str]:
        """Special character and encoding obfuscation payloads."""
        return [
            "!@#$%^&*()_+-=[]{}|;':\",./<>?",
            "%00",
            "%0a%0d",
            "\\x00\\x1a",
            "&#x27;",
            "&amp;",
            "%27%20OR%20%271%27%3D%271",
            "\\u0027",
            "\x00",
            "/../../../",
        ]

    def _static_remediation(self, vuln_type: str) -> str:
        """Fallback remediation when Gemini is unavailable."""
        remediations = {
            "SQL Injection": (
                "Use parameterized queries or prepared statements for all database interactions. "
                "Never concatenate user input directly into SQL strings. Implement an ORM "
                "and apply the principle of least privilege to database accounts."
            ),
            "Cross-Site Scripting": (
                "Sanitize all user-controlled input before rendering it in HTML. "
                "Implement a strict Content Security Policy (CSP). "
                "Use context-aware output encoding and modern frontend frameworks that escape by default."
            ),
            "Remote Code Execution": (
                "Never pass unsanitized user input to system commands. "
                "Use allow-lists for permitted commands. "
                "Apply strict file upload validation and sandboxing."
            ),
            "Broken Auth": (
                "Implement multi-factor authentication and secure session management. "
                "Use strong, randomly generated session tokens and enforce proper "
                "token expiration and invalidation on logout."
            ),
        }
        return remediations.get(
            vuln_type,
            "Apply strict input validation, follow the principle of least privilege, "
            "and conduct regular security reviews of the affected component.",
        )


# Module-level singleton
payload_engine = PayloadEngine()
