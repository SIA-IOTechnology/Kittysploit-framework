#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persistent encrypted credential vault command."""

from __future__ import annotations

import argparse
import getpass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.output_handler import print_empty, print_error, print_info, print_success, print_table, print_warning
from core.vault.persistent_store import get_persistent_vault, parse_ttl_option
from interfaces.command_system.base_command import BaseCommand
from interfaces.command_system.builtin.agent.credential_vault import get_credential_vault
from interfaces.command_system.builtin.agent.scope_lateral import (
    build_scope_index,
    index_credentials,
    propose_credential_reuse,
)


def _fmt_ts(value: float) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        return str(value)


def _load_agent_kb(framework: Any, run_id: str = "") -> Dict[str, Any]:
    try:
        from interfaces.command_system.builtin.agent.run_store import AgentPathService, AgentRunStore
    except ImportError:
        return {}

    paths = AgentPathService(framework)
    runs = AgentRunStore(paths, "probe").list_runs()
    if not runs:
        return {}

    target = str(run_id or "").strip()
    chosen = target if target and target in runs else runs[-1]
    store = AgentRunStore(paths, chosen)
    try:
        checkpoint = store.load_checkpoint()
    except (ValueError, OSError):
        return {}
    state = checkpoint.get("state") if isinstance(checkpoint, dict) else {}
    if not isinstance(state, dict):
        return {}
    kb = state.get("knowledge_base")
    return dict(kb) if isinstance(kb, dict) else {}


class VaultCommand(BaseCommand):
    """Manage the workspace encrypted credential vault."""

    @property
    def name(self) -> str:
        return "vault"

    @property
    def description(self) -> str:
        return "Encrypted persistent credential vault (origin, scope, expiration, reuse suggestions)"

    @property
    def usage(self) -> str:
        return "vault <list|add|show|revoke|suggest|import|status> [options]"

    def get_subcommands(self) -> List[str]:
        return ["list", "add", "show", "revoke", "suggest", "import", "status"]

    def __init__(self, framework=None, session=None, output_handler=None):
        super().__init__(framework, session, output_handler)
        self.parser = self._build_parser()

    def _store(self):
        if not getattr(self.framework, "is_encryption_loaded", lambda: False)():
            raise RuntimeError("Encryption is not unlocked. Restart KittySploit and enter the master password.")
        return get_persistent_vault(self.framework)

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="vault",
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  vault status
  vault list
  vault add --username admin --origin manual --source-host 10.0.0.5 --ttl 30d
  vault show cred_abc123def456
  vault revoke vault:persist:password:abc123def456
  vault suggest
  vault import --run-id agent_20260807T120000_ab12cd34ef
            """,
        )
        sub = parser.add_subparsers(dest="action")

        list_cmd = sub.add_parser("list", help="List stored credentials (metadata only)")
        list_cmd.add_argument("--expired", action="store_true", help="Include expired entries")

        add_cmd = sub.add_parser("add", help="Add a credential to the vault")
        add_cmd.add_argument("--username", "-u", default="", help="Username or identity")
        add_cmd.add_argument("--password", "-p", default="", help="Secret value (prompted if omitted)")
        add_cmd.add_argument("--kind", default="password", choices=["password", "token", "cookie", "api_key"])
        add_cmd.add_argument("--origin", default="manual", help="Source label (module name, manual, import)")
        add_cmd.add_argument("--source-host", default="", help="Host where the credential was discovered")
        add_cmd.add_argument("--scope-host", action="append", default=[], help="Limit reuse to host (repeatable)")
        add_cmd.add_argument("--scope-port", action="append", default=[], help="Limit reuse to port (repeatable)")
        add_cmd.add_argument("--protocol", default="", help="Protocol hint (ssh, smb, http, ...)")
        add_cmd.add_argument("--ttl", default="30d", help="Time-to-live: 24h, 7d, 30d, or seconds")
        add_cmd.add_argument("--notes", default="", help="Optional note")

        show_cmd = sub.add_parser("show", help="Show metadata for one credential")
        show_cmd.add_argument("token", help="credential_id or vault:persist: handle")

        revoke_cmd = sub.add_parser("revoke", help="Remove a credential from the vault")
        revoke_cmd.add_argument("token", help="credential_id or vault:persist: handle")

        suggest_cmd = sub.add_parser("suggest", help="Scope-bound credential reuse proposals")
        suggest_cmd.add_argument("--run-id", default="", help="Agent run checkpoint for scope context")

        import_cmd = sub.add_parser("import", help="Import credentials from an agent checkpoint")
        import_cmd.add_argument("--run-id", default="", help="Agent run id (latest if omitted)")
        import_cmd.add_argument("--ttl", default="30d", help="TTL for imported credentials")

        sub.add_parser("status", help="Show vault location and entry count")
        return parser

    def execute(self, args, **kwargs) -> bool:
        raw = list(args or [])
        if not raw or raw[0].lower() in {"help", "--help", "-h"}:
            print_info(self.parser.format_help())
            return True
        try:
            parsed = self.parser.parse_args(raw)
        except SystemExit:
            return True

        action = str(getattr(parsed, "action", "") or raw[0]).lower()
        handlers = {
            "list": self._list,
            "add": self._add,
            "show": self._show,
            "revoke": self._revoke,
            "suggest": self._suggest,
            "import": self._import,
            "status": self._status,
        }
        handler = handlers.get(action)
        if handler is None:
            print_error(f"Unknown vault subcommand: {action}")
            print_info(f"Usage: {self.usage}")
            return False
        try:
            return handler(parsed)
        except RuntimeError as exc:
            print_error(str(exc))
            return False

    def _status(self, _parsed) -> bool:
        store = self._store()
        rows = store.list_records(include_expired=True)
        print_success(f"Credential vault stored in workspace database (master-key encrypted)")
        print_info(f"Database: {store.storage_backend}")
        print_info(f"Workspace: {store.workspace} | entries: {len(rows)}")
        active = len([row for row in rows if not row.is_expired()])
        print_info(f"Active (non-expired): {active}")
        return True

    def _list(self, parsed) -> bool:
        store = self._store()
        rows = store.list_records(include_expired=bool(parsed.expired))
        if not rows:
            print_warning("No credentials in vault")
            return True
        table_rows = []
        for row in rows:
            scope = ",".join(row.scope_hosts[:3]) or "any in-scope"
            ports = ",".join(str(item) for item in row.scope_ports[:4]) or "-"
            table_rows.append([
                row.credential_id,
                row.username or "-",
                row.kind,
                row.source_host or "-",
                scope,
                ports,
                _fmt_ts(row.expires_at),
                "expired" if row.is_expired() else "active",
            ])
        print_table(
            ["ID", "User", "Kind", "Source", "Scope hosts", "Ports", "Expires", "Status"],
            table_rows,
            expand_to_terminal=True,
        )
        print_info("Secrets are encrypted in the workspace database with the master key.")
        return True

    def _add(self, parsed) -> bool:
        secret = str(parsed.password or "").strip()
        if not secret:
            try:
                secret = getpass.getpass("Secret value: ")
            except (KeyboardInterrupt, EOFError):
                print_warning("Cancelled")
                return False
        if not str(secret).strip():
            print_error("Secret value is required")
            return False

        ports: List[int] = []
        for item in parsed.scope_port or []:
            token = str(item or "").strip()
            if token.isdigit():
                ports.append(int(token))

        store = self._store()
        record = store.add(
            secret,
            kind=parsed.kind,
            username=parsed.username,
            origin=parsed.origin,
            source_host=parsed.source_host,
            scope_hosts=parsed.scope_host or [],
            scope_ports=ports,
            protocol_hint=parsed.protocol,
            ttl_seconds=parse_ttl_option(parsed.ttl),
            notes=parsed.notes,
        )
        print_success(f"Stored credential {record.credential_id}")
        print_info(f"Handle: {record.handle}")
        print_info(f"Expires: {_fmt_ts(record.expires_at)}")
        return True

    def _show(self, parsed) -> bool:
        store = self._store()
        record = store.get(parsed.token)
        if record is None:
            print_error(f"Credential not found: {parsed.token}")
            return False
        payload = record.to_public_dict()
        for key, value in payload.items():
            print_info(f"{key}: {value}")
        return True

    def _revoke(self, parsed) -> bool:
        store = self._store()
        if store.revoke(parsed.token):
            print_success(f"Revoked {parsed.token}")
            return True
        print_error(f"Credential not found: {parsed.token}")
        return False

    def _suggest(self, parsed) -> bool:
        kb = _load_agent_kb(self.framework, parsed.run_id)
        if not kb:
            print_warning("No agent checkpoint found; suggestions use campaign scope only if available")
            kb = {}
        index = build_scope_index(kb, state=None)
        credentials = index_credentials(kb, framework=self.framework)
        proposals = propose_credential_reuse(kb, scope_index=index, credentials=credentials)
        if not proposals:
            print_warning("No in-scope credential reuse proposals")
            print_info("Ensure scope is defined (lab manifest / campaign) and vault entries match destination hosts/ports.")
            return True
        rows = []
        for item in proposals:
            rows.append([
                item.action,
                f"{item.target_host}:{item.target_port}",
                item.protocol,
                item.credential_id[:12],
                item.module_hint or "-",
                item.reason,
            ])
        print_table(
            ["Action", "Target", "Protocol", "Credential", "Module hint", "Reason"],
            rows,
            expand_to_terminal=True,
        )
        print_info("Suggestions only — no automatic out-of-scope testing.")
        return True

    def _import(self, parsed) -> bool:
        kb = _load_agent_kb(self.framework, parsed.run_id)
        if not kb:
            print_error("No agent checkpoint found to import from")
            return False
        vault = get_credential_vault(kb=kb, framework=self.framework)
        store = self._store()
        imported = store.import_from_kb(kb, vault_resolver=vault)
        if not imported:
            print_warning("No importable credentials in checkpoint (handles must resolve or plaintext rows)")
            return True
        print_success(f"Imported {len(imported)} credential(s)")
        for row in imported:
            print_info(f"  {row.credential_id} -> {row.handle} ({row.username or 'no user'})")
        return True
