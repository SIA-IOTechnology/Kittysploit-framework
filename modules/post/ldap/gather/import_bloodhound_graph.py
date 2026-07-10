#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Import BloodHound JSON export into the agent attack graph.

Set ``export_path`` to nodes.json, edges.json, or a directory containing both.
The merged graph is stored in workspace/agent KB as ``attack_graph``.
"""

from kittysploit import *
from lib.protocols.ldap.ad_graph_import import load_bloodhound_export, merge_bloodhound_into_kb


class Module(Post):
    __info__ = {
        "name": "Import BloodHound Graph",
        "description": (
            "Merge BloodHound nodes/edges JSON into the agent attack graph for "
            "lightweight path planning without Neo4j."
        ),
        "author": "KittySploit Team",
        "session_type": SessionType.LDAP,
        "tags": ["ad", "ldap", "bloodhound", "graph", "import"],
        "agent": {
            "risk": "passive",
            "effects": ["file_read"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["ldap_access"],
                "produces_capabilities": ["admin_access"],
            },
        },
    }

    export_path = OptString("", "BloodHound export file or directory", True)
    domain = OptString("", "AD domain label for graph root (optional)", False)
    replace = OptBool(False, "Replace existing attack_graph instead of merging", False)

    def run(self):
        path = str(self.export_path or "").strip()
        if not path:
            print_error("export_path is required")
            return False

        nodes, edges = load_bloodhound_export(path)
        if not nodes and not edges:
            print_error(f"No BloodHound data loaded from {path}")
            return False

        print_success(f"Loaded BloodHound export: {len(nodes)} nodes, {len(edges)} edges")
        kb = {}
        if getattr(self, "framework", None) and hasattr(self.framework, "agent_state"):
            state = getattr(self.framework, "agent_state", None)
            if state and isinstance(getattr(state, "knowledge_base", None), dict):
                kb = state.knowledge_base

        merged = merge_bloodhound_into_kb(
            kb,
            path,
            domain=str(self.domain or "").strip(),
            replace=bool(self.replace),
        )
        print_info(f"Attack graph now has {merged} new node(s)")
        self.vulnerability_info = {
            "nodes": len(nodes),
            "edges": len(edges),
            "bloodhound_source": path,
        }
        return True
