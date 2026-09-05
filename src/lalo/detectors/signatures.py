"""Detection signatures (error strings, content markers)."""

from __future__ import annotations

import re

# DB error fragments across common engines -> SQL injection error signal.
SQL_ERRORS: tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "psqlexception",
    "syntax error at or near",
    "ora-00933",
    "ora-01756",
    "sqlite3::",
    "sqlite_error",
    "unrecognized token",
    "sqlstate",
    "odbc sql server driver",
    "npgsql.",
)

# /etc/passwd content -> path traversal / LFI read.
PASSWD_MARKER = re.compile(r"root:.*?:0:0:", re.MULTILINE)

# `id` command output -> command injection execution proof.
ID_OUTPUT = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\(")

# simple arithmetic in a payload -> SSTI evaluation check.
ARITHMETIC = re.compile(r"(\d{1,4})\s*\*\s*(\d{1,4})")
