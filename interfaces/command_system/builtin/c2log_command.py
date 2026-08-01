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
        return (
            "c2log [list|timeline|show] [--session ID] [--since 1h] "
            "[--status queued] [--limit N] [--json] [task_id]"
        )

    @property
    def help_text(self) -> str:
        return """
Show the C2 operations log for HTTP polling beacons (queued -> sent -> completed).
Stored in the framework workspace database (same DB unlocked by the master password).

Subcommands:
    list / timeline   Show recent tasks (default)
    show <task_id>    Full record including complete command and output
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
    c2log show 4ec588c5
    c2log timeline --limit 20 --json
        """

    def get_subcommands(self) -> List[str]:
        return ["list", "timeline", "show", "help"]

    def execute(self, args: List[str], **kwargs) -> bool:
        if args and args[0] in ("-h", "--help", "help"):
            self.show_help()
            return True

        rest = list(args or [])
        action = "list"
        if rest and rest[0].lower() in ("list", "timeline", "show"):
            action = rest[0].lower()
            rest = rest[1:]

        if action == "show":
            return self._show(rest)

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
            when = str(r.get("created_at") or "").replace("T", " ").rstrip("Z")
            cmd = str(r.get("command") or "").replace("\n", " ")
            table.append(
                [
                    when,
                    str(r.get("status") or ""),
                    str(r.get("session_id") or ""),
                    str(r.get("implant_id") or ""),
                    str(r.get("operator") or ""),
                    cmd,
                ]
            )

        print_table(
            headers,
            table,
            wrap_extra_headers=["Command", "Session", "Implant", "When", "Status"],
            prefer_single_line=True,
            expand_headers=["Command"],
        )
        print_info(f"{len(rows)} task(s)  store={log.storage_label()}")
        completed = sum(1 for r in rows if r.get("status") == "completed")
        if completed:
            print_success(f"{completed} completed")
        print_info("Full output: c2log show <task_id>")
        return True

    def _show(self, args: List[str]) -> bool:
        if not args:
            print_error("Usage: c2log show <task_id>")
            return False
        needle = str(args[0]).strip()
        try:
            log = get_ops_log(self.framework)
            rows = log.list_tasks(limit=500)
        except Exception as exc:
            print_error(f"Failed to read C2 ops log: {exc}")
            return False

        match = None
        for r in rows:
            tid = str(r.get("task_id") or "")
            if tid == needle or tid.startswith(needle):
                match = r
                break
        if not match:
            print_warning(f"No task matching {needle!r}")
            return False

        print_info(f"task_id:     {match.get('task_id')}")
        print_info(f"status:      {match.get('status')}")
        print_info(f"when:        {match.get('created_at')}")
        print_info(f"sent_at:     {match.get('sent_at')}")
        print_info(f"completed:   {match.get('completed_at')}")
        print_info(f"session:     {match.get('session_id')}")
        print_info(f"implant:     {match.get('implant_id')}")
        print_info(f"operator:    {match.get('operator')}")
        print_info(f"listener:    {match.get('listener_type')}")
        print_info(f"client_ip:   {match.get('client_ip')}")
        print_info("command:")
        print(str(match.get("command") or ""))
        out = match.get("output") or match.get("output_preview") or ""
        print_info("output:")
        print(str(out) if out else "(empty)")
        return True
