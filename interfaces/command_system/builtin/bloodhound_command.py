#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BloodHound import / BHCE helpers from the KittySploit console."""

from __future__ import annotations

from typing import List

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error, print_info, print_success, print_warning
from lib.protocols.ldap.ad_graph_import import (
    load_bloodhound_export,
    merge_bloodhound_into_kb,
)
from lib.protocols.ldap.bhce_client import client_from_env_or_opts


class BloodhoundCommand(BaseCommand):
    @property
    def name(self) -> str:
        return "bloodhound"

    @property
    def aliases(self) -> List[str]:
        return ["bh"]

    @property
    def description(self) -> str:
        return "Import AD graph exports into KittySploit (native LDAP path preferred)"

    @property
    def usage(self) -> str:
        return "bloodhound import <path> | bloodhound status | bloodhound bhce-version [--url URL]"

    @property
    def help_text(self) -> str:
        return """
Prefer native KittySploit AD modules first (no external binaries):

    LDAP session + scanner/ldap/* and post/ldap/gather/*
      kerberoastable_users, asrep_roastable, delegation_audit, gpo_attack_graph_enrich
    SMB GPO scanners: scanner/smb/gpo_local_group_audit, gpo_registry_audit
    Host recon: post/shell/windows/gather/enum_system, privilege_escalation_surface, …

Graph import (when you already have a zip/json export):

    bloodhound import <zip|dir|json>   Merge into agent attack_graph
    bloodhound status                 Show bloodhound_export_path / graph stats

Optional external (requires PE in data/assemblies/):

    use post/shell/windows/gather/sharphound_collect   # SharpHound.exe
    bloodhound bhce-version / bhce-upload              # BloodHound CE API
        """

    def get_subcommands(self) -> List[str]:
        return ["import", "status", "bhce-version", "bhce-upload", "help"]

    def execute(self, args: List[str], **kwargs) -> bool:
        if not args or args[0] in ("-h", "--help", "help"):
            self.show_help()
            return True
        sub = args[0].lower()
        if sub == "import":
            return self._import(args[1:])
        if sub == "status":
            return self._status()
        if sub == "bhce-version":
            return self._bhce_version(args[1:])
        if sub == "bhce-upload":
            return self._bhce_upload(args[1:])
        print_error(f"Unknown subcommand: {sub}")
        return False

    def _kb(self):
        state = getattr(self.framework, "agent_state", None)
        if state and isinstance(getattr(state, "knowledge_base", None), dict):
            return state.knowledge_base
        # ephemeral fallback attached to framework
        kb = getattr(self.framework, "_bloodhound_kb", None)
        if not isinstance(kb, dict):
            kb = {}
            try:
                self.framework._bloodhound_kb = kb
            except Exception:
                pass
        return kb

    def _import(self, args: List[str]) -> bool:
        if not args:
            print_error("Usage: bloodhound import <path>")
            return False
        path = args[0]
        nodes, edges = load_bloodhound_export(path)
        if not nodes and not edges:
            print_error(f"No BloodHound data in {path}")
            return False
        kb = self._kb()
        added = merge_bloodhound_into_kb(kb, path)
        kb["bloodhound_export_path"] = path
        from lib.protocols.ldap.ad_graph_import import bloodhound_to_attack_graph

        kb["bloodhound_graph"] = bloodhound_to_attack_graph(nodes, edges)
        print_success(
            f"Imported {len(nodes)} nodes / {len(edges)} edges (+{added} new nodes in attack_graph)"
        )
        print_info(f"bloodhound_export_path = {path}")
        return True

    def _status(self) -> bool:
        kb = self._kb()
        path = kb.get("bloodhound_export_path") or "(none)"
        stats = kb.get("bloodhound_stats") or {}
        ag = kb.get("attack_graph") if isinstance(kb.get("attack_graph"), dict) else {}
        print_info(f"export_path: {path}")
        print_info(f"bloodhound_stats: {stats or '(n/a)'}")
        print_info(
            f"attack_graph: {len(ag.get('nodes') or [])} nodes / {len(ag.get('edges') or [])} edges"
        )
        overlay = kb.get("bloodhound_graph") if isinstance(kb.get("bloodhound_graph"), dict) else {}
        if overlay:
            print_info(
                f"bloodhound_overlay: {len(overlay.get('nodes') or [])} nodes / "
                f"{len(overlay.get('edges') or [])} edges"
            )
        return True

    def _parse_url_token(self, args: List[str]):
        url = ""
        token = ""
        i = 0
        while i < len(args):
            if args[i] == "--url" and i + 1 < len(args):
                url = args[i + 1]
                i += 2
                continue
            if args[i] == "--token" and i + 1 < len(args):
                token = args[i + 1]
                i += 2
                continue
            i += 1
        return url, token

    def _bhce_version(self, args: List[str]) -> bool:
        url, token = self._parse_url_token(args)
        client = client_from_env_or_opts(base_url=url, token_key=token)
        if not client:
            print_error("Set --url or KITTYSPLOIT_BHCE_URL")
            return False
        try:
            ver = client.version()
            print_success(f"BHCE OK: {ver}")
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def _bhce_upload(self, args: List[str]) -> bool:
        if not args:
            print_error("Usage: bloodhound bhce-upload <file> [--url URL] [--token TOK]")
            return False
        path = args[0]
        url, token = self._parse_url_token(args[1:])
        client = client_from_env_or_opts(base_url=url, token_key=token)
        if not client:
            print_error("Set --url or KITTYSPLOIT_BHCE_URL")
            return False
        try:
            result = client.upload_file(path)
            print_success(f"Upload result: {result}")
            return True
        except Exception as exc:
            print_warning(str(exc))
            return False
