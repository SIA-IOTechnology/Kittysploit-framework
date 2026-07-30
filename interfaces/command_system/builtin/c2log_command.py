#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""List C2 implant task/response audit log."""

from __future__ import annotations

import argparse
import json
from typing import List

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error, print_info, print_success, print_table, print_warning
from lib.c2.ops_log import get_ops_log


class C2LogCommand(BaseCommand):
    """Show HTTP polling / beacon task timeline."""

    @property
    def name(self) -> str:
        return "c2log"

    @property
    def aliases(self) -> List[str]:
        return ["c2ops", "beaconlog"]

    @property
    def description(self) -> str:
        return "Show C2 implant task/response audit log"

    @property
    def usage(self) -> str:
        return "c2log [list|timeline] [--session ID] [--since 1h] [--status queued] [--limit N] [--json]"

    @property
    def help_text(self) -> str:
        return """
Show the C2 operations log for HTTP polling beacons (queued -> sent -> completed).

Subcommands:
    list / timeline   Show recent tasks (default)
    help              Show this help

Options:
    --session ID      Filter by framework session id
    --implant ID      Filter by implant / client id
    --status STATUS   queued | sent | completed | failed | killed
    --since WHEN      Relative (1h, 30m, 2d) or ISO timestamp
    --limit N         Max rows (default 50)
    --json            Machine-readable JSON output

Examples:
    c2log
    c2log --since 1h
    c2log --session abc123 --status completed
    c2log timeline --limit 20 --json
        """

    def get_subcommands(self) -> List[str]:
        return ["list", "timeline", "help"]

    def execute(self, args: List[str], **kwargs) -> bool:
        if args and args[0] in ("-h", "--help", "help"):
            self.show_help()
            return True

        rest = list(args or [])
        if rest and rest[0].lower() in ("list", "timeline"):
            rest = rest[1:]

        parser = argparse.ArgumentParser(prog="c2log", add_help=True)
        parser.add_argument("--session", default=None)
        parser.add_argument("--implant", default=None)
        parser.add_argument("--status", default=None)
        parser.add_argument("--since", default=None)
        parser.add_argument("--limit", type=int, default=50)
        parser.add_argument("--json", action="store_true")

        try:
            parsed = parser.parse_args(rest)
        except SystemExit:
            return False

        try:
            log = get_ops_log(self.framework)
            rows = log.list_tasks(
                session_id=parsed.session,
                implant_id=parsed.implant,
                status=parsed.status,
                since=parsed.since,
                limit=int(parsed.limit or 50),
            )
        except ValueError as exc:
            print_error(str(exc))
            return False
        except Exception as exc:
            print_error(f"Failed to read C2 ops log: {exc}")
            return False

        if parsed.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return True

        if not rows:
            print_warning("No C2 tasks found (try running commands on a polling session first)")
            return True

        headers = ["When", "Status", "Session", "Implant", "Operator", "Command"]
        table = []
        for r in rows:
            when = str(r.get("created_at") or "")[:19].replace("T", " ")
            cmd = str(r.get("command") or "").replace("\n", " ")
            if len(cmd) > 48:
                cmd = cmd[:45] + "..."
            sid = str(r.get("session_id") or "")
            if len(sid) > 10:
                sid = sid[:8] + ".."
            implant = str(r.get("implant_id") or "")
            if len(implant) > 14:
                implant = implant[:12] + ".."
            table.append(
                [
                    when,
                    str(r.get("status") or ""),
                    sid,
                    implant,
                    str(r.get("operator") or ""),
                    cmd,
                ]
            )

        print_table(headers, table)
        print_info(f"{len(rows)} task(s)  log={log.jsonl_path}")
        completed = sum(1 for r in rows if r.get("status") == "completed")
        if completed:
            print_success(f"{completed} completed")
        return True
