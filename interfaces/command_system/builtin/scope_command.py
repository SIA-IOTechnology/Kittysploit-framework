#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Scope command — engagement allowlist, rate limits, and audit."""

from __future__ import annotations

import argparse
from typing import List

from core.output_handler import print_empty, print_error, print_info, print_success, print_table, print_warning
from interfaces.command_system.base_command import BaseCommand


class ScopeCommand(BaseCommand):
    """Manage proactive engagement scope enforcement."""

    @property
    def name(self) -> str:
        return "scope"

    @property
    def description(self) -> str:
        return "Manage engagement scope (allowlist, rate limit, destructive confirmations, audit)"

    @property
    def usage(self) -> str:
        return "scope <enable|disable|status|allow|rate|confirm|check|audit> [options]"

    def get_subcommands(self) -> List[str]:
        return ["enable", "disable", "status", "allow", "rate", "confirm", "check", "audit"]

    def __init__(self, framework=None, session=None, output_handler=None):
        super().__init__(framework, session, output_handler)
        self.parser = self._build_parser()

    def _scope_manager(self):
        return getattr(self.framework, "scope_manager", None)

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="scope",
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  scope enable
  scope allow ip 10.0.0.0/24
  scope allow domain *.client.example
  scope rate 30 60
  scope confirm on
  scope check 10.0.0.15
  scope audit --limit 20
            """,
        )
        sub = parser.add_subparsers(dest="action")

        sub.add_parser("enable", help="Enable scope enforcement")
        sub.add_parser("disable", help="Disable scope enforcement")
        sub.add_parser("status", help="Show scope configuration")

        allow = sub.add_parser("allow", help="Manage allowlist entries")
        allow_sub = allow.add_subparsers(dest="allow_action")
        allow_add = allow_sub.add_parser("add", help="Add allowlist entry")
        allow_add.add_argument("kind", choices=["ip", "domain"], help="Entry type")
        allow_add.add_argument("value", help="IP, CIDR, domain, or *.domain")
        allow_rm = allow_sub.add_parser("remove", help="Remove allowlist entry")
        allow_rm.add_argument("kind", choices=["ip", "domain"])
        allow_rm.add_argument("value")
        allow_sub.add_parser("list", help="List allowlist entries")

        rate = sub.add_parser("rate", help="Configure per-target rate limit")
        rate.add_argument("max_actions", nargs="?", type=int, help="Max actions per window (0=off)")
        rate.add_argument("window_sec", nargs="?", type=int, default=60, help="Window in seconds")

        confirm = sub.add_parser("confirm", help="Toggle destructive-action confirmation")
        confirm.add_argument("mode", choices=["on", "off"], nargs="?", help="on or off")

        check = sub.add_parser("check", help="Test if a target is in scope")
        check.add_argument("target", help="IP or domain")

        audit = sub.add_parser("audit", help="Show recent scope audit events")
        audit.add_argument("--limit", type=int, default=20, help="Number of events")
        return parser

    def execute(self, args, **kwargs) -> bool:
        if not args:
            args = ["--help"]

        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        manager = self._scope_manager()
        if manager is None:
            print_error("Scope manager is not available")
            return False

        action = parsed.action
        if action == "enable":
            manager.enable()
            print_success("Scope enforcement enabled")
            print_warning("Allowlist is deny-by-default when enabled — add entries with: scope allow add")
            return True
        if action == "disable":
            manager.disable()
            print_success("Scope enforcement disabled")
            return True
        if action == "status":
            return self._show_status(manager)
        if action == "allow":
            return self._handle_allow(manager, parsed)
        if action == "rate":
            return self._handle_rate(manager, parsed)
        if action == "confirm":
            return self._handle_confirm(manager, parsed)
        if action == "check":
            return self._handle_check(manager, parsed)
        if action == "audit":
            return self._handle_audit(manager, parsed)

        self.parser.print_help()
        return True

    def _show_status(self, manager) -> bool:
        data = manager.status_dict()
        print_info(f"Workspace: {data['workspace']}")
        print_info(f"Enforcement: {'enabled' if data['enabled'] else 'disabled'}")
        print_info(f"Destructive confirmation: {'on' if data['require_confirm_destructive'] else 'off'}")
        print_info(
            f"Rate limit: {data['rate_limit_max']} / {data['rate_limit_window_sec']}s"
            if data["rate_limit_max"] > 0
            else "Rate limit: disabled"
        )
        print_info(f"Config: {data['config_path']}")
        print_info(f"Audit log: {data['audit_path']}")
        print_empty()
        print_info("Allowed IPs/CIDRs:")
        for entry in data["allowed_ips"] or ["(none)"]:
            print_info(f"  {entry}")
        print_empty()
        print_info("Allowed domains:")
        for entry in data["allowed_domains"] or ["(none)"]:
            print_info(f"  {entry}")
        return True

    def _handle_allow(self, manager, parsed) -> bool:
        if not parsed.allow_action:
            print_error("Usage: scope allow <add|remove|list> ...")
            return False
        if parsed.allow_action == "list":
            print_info("IPs/CIDRs:")
            for entry in manager.allowed_ips or ["(none)"]:
                print_info(f"  {entry}")
            print_info("Domains:")
            for entry in manager.allowed_domains or ["(none)"]:
                print_info(f"  {entry}")
            return True
        if parsed.allow_action == "add":
            try:
                if parsed.kind == "ip":
                    manager.add_allow_ip(parsed.value)
                else:
                    manager.add_allow_domain(parsed.value)
                print_success(f"Added {parsed.kind} allowlist entry: {parsed.value}")
                return True
            except Exception as exc:
                print_error(str(exc))
                return False
        if parsed.allow_action == "remove":
            removed = (
                manager.remove_allow_ip(parsed.value)
                if parsed.kind == "ip"
                else manager.remove_allow_domain(parsed.value)
            )
            if removed:
                print_success(f"Removed {parsed.kind} entry: {parsed.value}")
                return True
            print_warning("Entry not found")
            return False
        return False

    def _handle_rate(self, manager, parsed) -> bool:
        if parsed.max_actions is None:
            print_info(
                f"Current rate limit: {manager.rate_limit_max} actions / "
                f"{manager.rate_limit_window_sec}s (0 = disabled)"
            )
            return True
        manager.set_rate_limit(parsed.max_actions, parsed.window_sec or 60)
        if parsed.max_actions <= 0:
            print_success("Rate limit disabled")
        else:
            print_success(
                f"Rate limit set to {parsed.max_actions} actions per {parsed.window_sec}s per target"
            )
        return True

    def _handle_confirm(self, manager, parsed) -> bool:
        if not parsed.mode:
            state = "on" if manager.require_confirm_destructive else "off"
            print_info(f"Destructive confirmation: {state}")
            return True
        manager.require_confirm_destructive = parsed.mode == "on"
        manager.save()
        manager.audit("confirm_mode_changed", {"enabled": manager.require_confirm_destructive})
        print_success(f"Destructive confirmation: {parsed.mode}")
        return True

    def _handle_check(self, manager, parsed) -> bool:
        decision = manager.is_target_allowed(parsed.target)
        if decision.allowed:
            print_success(decision.reason)
        else:
            print_error(decision.reason)
        return decision.allowed or not manager.enabled

    def _handle_audit(self, manager, parsed) -> bool:
        records = manager.read_audit(parsed.limit)
        if not records:
            print_info("No scope audit events recorded yet")
            return True
        rows = []
        for record in records:
            payload = record.get("payload") or {}
            detail = payload.get("reason") or payload.get("module") or json_preview(payload)
            rows.append([record.get("timestamp", ""), record.get("event", ""), detail])
        print_table(["Timestamp", "Event", "Detail"], rows, max_width=120)
        return True


def json_preview(payload) -> str:
    if not payload:
        return ""
    parts = [f"{key}={value}" for key, value in list(payload.items())[:3]]
    return ", ".join(parts)
