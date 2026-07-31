#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MSSQL privilege / impersonation check on an active session."""

from kittysploit import *
from lib.protocols.mssql.mssql_client import MSSQLClient


class Module(Post, MSSQLClient):
    __info__ = {
        "name": "MSSQL Priv / Impersonate Check",
        "description": (
            "Reports whether the session user is sysadmin and which logins can be "
            "impersonated (NetExec: -M mssql_priv / enum_impersonate)."
        ),
        "author": ["KittySploit Team"],
        "session_type": SessionType.MSSQL,
        "tags": ["mssql", "impersonate", "sysadmin", "post", "netexec"],
        "references": ["https://www.netexec.wiki/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
        },
    }

    def run(self):
        try:
            rows = self.execute_query(
                "SELECT SYSTEM_USER AS sysuser, "
                "IS_SRVROLEMEMBER('sysadmin') AS is_sa, "
                "ORIGINAL_LOGIN() AS original"
            ) or []
            row0 = rows[0] if rows else {}
            if isinstance(row0, dict):
                sysuser = row0.get("sysuser", "?")
                is_sa = row0.get("is_sa", 0)
                original = row0.get("original", "?")
            else:
                sysuser, is_sa, original = (list(row0) + [None, None, None])[:3]
            print_success(
                f"SYSTEM_USER={sysuser} ORIGINAL_LOGIN={original} sysadmin={bool(is_sa)}"
            )

            targets = self.execute_query(
                """
                SELECT pr.name AS name
                FROM sys.server_principals AS pr
                WHERE pr.type IN ('S','U')
                  AND HAS_PERMS_BY_NAME(pr.name, 'LOGIN', 'IMPERSONATE') = 1
                """
            ) or []
            names = []
            for r in targets:
                if isinstance(r, dict):
                    n = r.get("name")
                else:
                    n = r[0] if r else None
                if n:
                    names.append(n)
            print_info(f"Impersonatable logins ({len(names)}):")
            for n in names:
                print_info(f"  - {n}")
            if any(str(n).lower() == "sa" for n in names):
                print_warning("Can impersonate sa — chain to post/mssql/manage/xp_cmdshell")
            return True
        except ProcedureError:
            raise
        except Exception as exc:
            print_error(str(exc))
            return False
