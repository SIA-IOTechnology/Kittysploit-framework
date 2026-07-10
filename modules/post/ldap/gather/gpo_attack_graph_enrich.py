#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Merge GPO audit findings into the agent attack graph.

Accepts a JSON export from GPO scanners plus an optional LDAP scope map.
"""

from __future__ import annotations

import json
from pathlib import Path

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.gpo_graph_enrich import merge_gpo_findings_into_kb
from lib.protocols.ldap.gpo_helpers import map_gpos_to_computers


class Module(Post, Ad_client):
    __info__ = {
        "name": "GPO Attack Graph Enrich",
        "description": (
            "Merge GPO local group / privilege findings into the agent attack graph "
            "using LDAP-derived GPO scope when available."
        ),
        "author": "KittySploit Team",
        "session_type": SessionType.LDAP,
        "tags": ["ad", "ldap", "gpo", "graph", "bloodhound"],
        "agent": {
            "risk": "passive",
            "effects": ["file_read"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "gpo_graph_enriched"],
            "chain": {
                "consumes_capabilities": ["ldap_access"],
                "produces_capabilities": ["admin_access"],
            },
        },
    }

    findings_file = OptString("", "JSON file with GPO findings (findings[])", True)
    scope_file = OptString("", "Optional JSON file with gpo_computer_map", False)
    domain = OptString("", "AD domain label for graph root (optional)", False)
    target = OptString("", "Domain controller for live LDAP scope lookup", False)
    username = OptString("", "Bind user (DOMAIN\\user or user@domain)", False)
    password = OptString("", "Bind password", False)

    def _load_json(self, path: str):
        p = Path(str(path or "").strip())
        if not p.is_file():
            return None
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))

    def run(self):
        raw = self._load_json(str(self.findings_file or ""))
        if not isinstance(raw, dict):
            print_error("findings_file must contain a JSON object")
            return False

        findings = raw.get("findings") or raw.get("group_findings") or []
        if not isinstance(findings, list) or not findings:
            print_error("No GPO findings found in input file")
            return False

        gpo_computer_map = {}
        scope_raw = self._load_json(str(self.scope_file or ""))
        if isinstance(scope_raw, dict):
            gpo_computer_map = scope_raw.get("gpo_computer_map") or scope_raw.get("gpo_scope") or {}

        if not gpo_computer_map and str(self.target or "").strip():
            if self.conn:
                _, live_map = map_gpos_to_computers(self)
                gpo_computer_map = live_map
            else:
                print_warning("LDAP scope lookup failed; graph edges may be incomplete")

        kb = {}
        if getattr(self, "framework", None) and hasattr(self.framework, "agent_state"):
            state = getattr(self.framework, "agent_state", None)
            if state and isinstance(getattr(state, "knowledge_base", None), dict):
                kb = state.knowledge_base

        added = merge_gpo_findings_into_kb(
            kb,
            findings,
            gpo_computer_map,
            domain=str(self.domain or "").strip(),
        )
        print_success(f"Added {added} GPO-derived edge(s) to attack graph")
        self.vulnerability_info = {
            "edges_added": added,
            "findings_loaded": len(findings),
            "gpo_scope_entries": len(gpo_computer_map),
        }
        return added > 0
