"""Detection signatures (error strings, content markers)."""

from __future__ import annotations

import re

# DB error fragments across common engines -> SQL injection error signal.
SQL_ERRORS: tuple[str, ...] = (
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "warning: mysql",
    "warning: mysqli",
    "mysql_fetch",
    "valid mysql result",
    "com.mysql.jdbc",
    "mysqlclient.",
    "check the manual that corresponds to your mysql server version",
    # PostgreSQL
    "psqlexception",
    "syntax error at or near",
    "pg_query()",
    "pg_exec()",
    "npgsql.",
    "unterminated quoted string at or near",
    # Microsoft SQL Server
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "mssql_query()",
    "system.data.sqlclient.sqlexception",
    # Oracle
    "ora-00933",
    "ora-00921",
    "ora-00936",
    "ora-01756",
    "quoted string not properly terminated",
    "oracle error",
    # SQLite
    "sqlite3::",
    "sqlite_error",
    "sqlite3.operationalerror",
    "unrecognized token",
    # DB2 / generic
    "db2 sql error",
    "sqlstate",
)

# NoSQL (Mongo/Couch/etc.) error fragments -> NoSQL injection signal.
NOSQL_ERRORS: tuple[str, ...] = (
    "mongoerror",
    "mongodb.driver",
    "unexpected token",
    "$where",
    "bson.errors",
    "couchdb",
    "unterminated string in json",
)

# Cloud-metadata response content markers -> in-band SSRF reaching IMDS.
METADATA_MARKERS: tuple[str, ...] = (
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "accesskeyid",
    "computemetadata",
    "meta-data/",
)

# /etc/passwd content -> path traversal / LFI read.
PASSWD_MARKER = re.compile(r"root:.*?:0:0:", re.MULTILINE)

# `id` command output -> command injection execution proof.
ID_OUTPUT = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\(")

# simple arithmetic in a payload -> SSTI evaluation check.
ARITHMETIC = re.compile(r"(\d{1,4})\s*\*\s*(\d{1,4})")
