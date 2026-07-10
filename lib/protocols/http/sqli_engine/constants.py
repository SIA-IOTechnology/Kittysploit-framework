#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared SQLi detection constants."""

from __future__ import annotations

from typing import Dict, List, Tuple

# Strong DB/driver error substrings (avoid generic tokens like bare "mysql").
SQLI_ERROR_TOKENS: Tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysqli_",
    "mysqli_sql_exception",
    "mysql_fetch",
    "sql syntax",
    "syntax error near",
    "quoted string not properly terminated",
    "unclosed quotation mark",
    "unclosed quotation",
    "sqlite error",
    "sqlite3.operationalerror",
    "sqlite exception",
    "pg_query(",
    "pg_exec(",
    "warning: pg_",
    "postgresql query failed",
    "sqlstate[",
    "ora-01756",
    "ora-0",
    "oracle error",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
    "microsoft ole db provider for odbc",
    "odbc driver manager",
    "sql server",
    "django.db.utils",
    "operationalerror",
)

# Map error tokens → DBMS hint (first match wins).
DBMS_ERROR_HINTS: Tuple[Tuple[str, str], ...] = (
    ("warning: mysql", "mysql"),
    ("mysqli_", "mysql"),
    ("mysql_fetch", "mysql"),
    ("you have an error in your sql syntax", "mysql"),
    ("warning: pg_", "postgresql"),
    ("pg_query(", "postgresql"),
    ("postgresql query failed", "postgresql"),
    ("sqlstate[", "postgresql"),
    ("sqlite", "sqlite"),
    ("ora-", "oracle"),
    ("oracle error", "oracle"),
    ("odbc sql server", "mssql"),
    ("microsoft ole db provider for sql", "mssql"),
    ("sql server", "mssql"),
)

DETECTION_CONFIDENCE: Dict[str, int] = {
    "error": 91,
    "boolean": 74,
    "boolean_numeric": 71,
    "time": 82,
    "union": 85,
}

TECHNIQUE_LABELS: Dict[str, str] = {
    "error": "Error-based",
    "boolean": "Boolean-based",
    "boolean_numeric": "Boolean-based (numeric)",
    "time": "Time-based",
    "union": "Union-based",
}

TECHNIQUE_TO_DETECTION_KIND: Dict[str, str] = {
    "error": "sqli_error",
    "boolean": "sqli_boolean",
    "boolean_numeric": "sqli_boolean_numeric",
    "time": "sqli_time",
    "union": "sqli_error",
}

TECHNIQUE_TO_RESULT_NAME: Dict[str, str] = {
    "error": "SQL Injection (error-based)",
    "boolean": "SQL Injection (boolean-based)",
    "boolean_numeric": "SQL Injection (boolean-based, numeric context)",
    "time": "SQL Injection (time-based)",
    "union": "SQL Injection (union-based)",
}
