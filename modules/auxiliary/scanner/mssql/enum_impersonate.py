#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate MSSQL impersonation rights (NetExec: -M enum_impersonate)."""

from __future__ import annotations

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "MSSQL Enum Impersonate",
        "description": (
            "Lists logins the current SQL user can EXECUTE AS "
            "(NetExec: nxc mssql -M enum_impersonate)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["mssql", "database", "impersonate", "auxiliary", "netexec", "privesc"],
        "references": ["https://www.netexec.wiki/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    target = OptString("", "MSSQL host", True)
    port = OptPort(1433, "MSSQL port", True)
    username = OptString("", "SQL / Windows username", True)
    password = OptString("", "Password", True)
    database = OptString("master", "Database", False)
    windows_auth = OptBool(
        False,
        "Use Windows auth (domain\\user). Default is SQL auth (--local-auth in NetExec).",
        False,
    )

    def run(self):
        host = str(self.target or "").strip()
        user = str(self.username or "").strip()
        password = str(self.password or "")
        if not host or not user:
            print_error("target and username are required")
            return {"error": "missing_options"}
        try:
            import pymssql
        except ImportError:
            print_error("pymssql is required")
            return {"error": "pymssql_missing"}

        login = user
        if self.windows_auth and "\\" not in user and "@" not in user:
            print_warning("windows_auth set but username has no DOMAIN\\ prefix")

        try:
            conn = pymssql.connect(
                server=host,
                port=int(self.port or 1433),
                user=login,
                password=password,
                database=str(self.database or "master"),
                login_timeout=10,
            )
        except Exception as exc:
            print_error(f"MSSQL login failed: {exc}")
            return {"error": str(exc)[:200]}

        try:
            cur = conn.cursor()
            cur.execute("SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')")
            row = cur.fetchone()
            sysuser = row[0] if row else user
            is_sa = bool(row[1]) if row and row[1] is not None else False
            print_success(f"Authenticated as {sysuser} (sysadmin={is_sa})")

            # Principals we can impersonate
            cur.execute(
                """
                SELECT DISTINCT b.name
                FROM sys.server_permissions a
                INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
                WHERE a.permission_name = 'IMPERSONATE'
                  AND a.grantee_principal_id = (
                      SELECT principal_id FROM sys.server_principals
                      WHERE name = SYSTEM_USER
                  )
                UNION
                SELECT name FROM sys.server_principals
                WHERE type IN ('S','U') AND name <> SYSTEM_USER
                  AND HAS_PERMS_BY_NAME(name, 'LOGIN', 'IMPERSONATE') = 1
                """
            )
            targets = [r[0] for r in (cur.fetchall() or []) if r and r[0]]
            # Also try classic NetExec query
            if not targets:
                cur.execute(
                    """
                    SELECT pr.name
                    FROM sys.server_principals AS pr
                    WHERE pr.type IN ('S','U')
                      AND pr.name <> 'sa'
                      AND HAS_PERMS_BY_NAME(pr.name, 'LOGIN', 'IMPERSONATE') = 1
                    """
                )
                targets = [r[0] for r in (cur.fetchall() or []) if r and r[0]]

            print_success(f"Users with impersonation rights from {sysuser}:")
            if not targets:
                print_info("  (none)")
            for t in targets:
                tag = ""
                try:
                    safe = str(t).replace("'", "''")
                    cur.execute(
                        f"EXECUTE AS LOGIN = '{safe}'; "
                        "SELECT IS_SRVROLEMEMBER('sysadmin'); REVERT;"
                    )
                    flag = cur.fetchone()
                    if flag and flag[0]:
                        tag = " (sysadmin)"
                except Exception:
                    pass
                print_info(f"  - {t}{tag}")
            return {
                "user": sysuser,
                "sysadmin": is_sa,
                "impersonate": targets,
            }
        finally:
            try:
                conn.close()
            except Exception:
                pass
