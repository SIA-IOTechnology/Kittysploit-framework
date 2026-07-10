#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from collections import defaultdict

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Attack Graph",
        "description": "Build an IAM and resource attack graph for the current principal and project",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "attack-graph", "iam", "cloud"],
        "references": [
            "https://cloud.google.com/iam/docs/overview",
            "https://attack.mitre.org/tactics/TA0008/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 25,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    include_network = OptBool(True, "Include Internet-facing firewall nodes", False)
    include_exposure = OptBool(True, "Include public IAM binding nodes", False)
    max_service_accounts = OptInteger(40, "Maximum service accounts to include in the graph", False)
    show_graph = OptBool(True, "Render an ASCII attack tree in the console", False)
    show_mermaid = OptBool(True, "Print a Mermaid flowchart block in the console", False)
    max_sample_resources = OptInteger(5, "Sample resources shown per service account before grouping", False)
    auto_export_output = OptBool(True, "Write JSON/DOT/Mermaid files under output/gcp/<project_id>/", False)
    export_json = OptString("", "JSON output path relative to output/ (optional override)", False)
    export_dot = OptString("", "Graphviz DOT path relative to output/ (optional override)", False)
    export_mermaid = OptString("", "Mermaid path relative to output/ (optional override)", False)
    verbose = OptBool(False, "Print raw edge list in console output", False)

    def run(self):
        try:
            print_info("Building GCP attack graph...")
            principal = self._gcp_client_email()
            project_id = self._gcp_project_id()
            if not principal:
                print_error("Could not resolve current principal (whoami)")
                return False

            print_info(f"Project: {project_id or 'unknown'}")
            print_info(f"Principal: {principal}")
            print_info("=" * 80)

            graph = self._gcp_build_attack_graph(
                principal=principal,
                include_network=bool(self.include_network),
                include_exposure=bool(self.include_exposure),
                max_service_accounts=int(self.max_service_accounts or 40),
            )
            nodes = graph.get("nodes") or []
            edges = graph.get("edges") or []
            node_map, forward = self._index_graph(graph)
            root_id = f"principal:{principal}"

            node_types: dict = {}
            edge_types: dict = {}
            for node in nodes:
                node_types[node.get("type", "unknown")] = node_types.get(node.get("type", "unknown"), 0) + 1
            for edge in edges:
                edge_types[edge.get("relationship", "unknown")] = edge_types.get(edge.get("relationship", "unknown"), 0) + 1

            print_success(f"Graph built: {len(nodes)} node(s), {len(edges)} edge(s)")
            for node_type, count in sorted(node_types.items()):
                print_info(f"  nodes[{node_type}]: {count}")
            for edge_type, count in sorted(edge_types.items()):
                print_info(f"  edges[{edge_type}]: {count}")

            if self.show_graph:
                print_info("=" * 80)
                print_status("Attack graph")
                self._print_ascii_graph(root_id, node_map, forward, int(self.max_sample_resources or 5))

            mermaid = self._to_mermaid(graph, root_id)
            if self.show_mermaid and mermaid:
                print_info("=" * 80)
                print_status("Mermaid flowchart")
                print_info("Paste into https://mermaid.live or any Markdown viewer:")
                print_info(mermaid)

            if self.verbose:
                print_info("=" * 80)
                for edge in edges[:50]:
                    print_info(
                        f"  {self._node_label(edge.get('from'), node_map)} "
                        f"--[{edge.get('relationship')}]--> "
                        f"{self._node_label(edge.get('to'), node_map)}"
                    )

            export_base = f"gcp/{project_id or 'project'}/attack_graph"
            should_export = bool(self.auto_export_output) or any(
                str(getattr(self, name, "") or "").strip()
                for name in ("export_json", "export_dot", "export_mermaid")
            )
            if should_export:
                json_path = self._gcp_export_json(
                    str(self.export_json or ""),
                    graph,
                    default_name=f"{export_base}.json" if self.auto_export_output else "",
                )
                if json_path:
                    print_success(f"Attack graph JSON exported to {json_path}")

                dot_path = self._gcp_export_text(
                    str(self.export_dot or ""),
                    self._to_dot(graph),
                    default_name=f"{export_base}.dot" if self.auto_export_output else "",
                )
                if dot_path:
                    print_success(f"DOT graph exported to {dot_path}")

                if mermaid:
                    mermaid_path = self._gcp_export_text(
                        str(self.export_mermaid or ""),
                        mermaid,
                        default_name=f"{export_base}.mmd" if self.auto_export_output else "",
                    )
                    if mermaid_path:
                        print_success(f"Mermaid graph exported to {mermaid_path}")

            print_info("=" * 80)
            return self.module_result(success=True, data=graph)
        except Exception as exc:
            print_error(f"GCP attack graph analysis failed: {exc}")
            return False

    @staticmethod
    def _index_graph(graph):
        node_map = {node.get("id"): node for node in (graph.get("nodes") or []) if node.get("id")}
        forward = defaultdict(list)
        for edge in graph.get("edges") or []:
            source = edge.get("from")
            if source:
                forward[source].append(edge)
        return node_map, forward

    def _node_label(self, node_id, node_map):
        node = node_map.get(node_id) or {}
        label = str(node.get("label") or node_id)
        node_type = str(node.get("type") or "node")
        if len(label) > 72:
            label = label[:69] + "..."
        glyphs = {
            "principal": "#",
            "role": "@",
            "privesc_path": "!",
            "service_account": "$",
            "compute_instance": "VM",
            "cloud_function_v1": "F1",
            "cloud_function_v2": "F2",
            "cloud_run_job": "CR",
            "public_exposure": "*",
            "network_path": "NET",
        }
        glyph = glyphs.get(node_type, "?")
        extra = ""
        if node_type == "privesc_path" and node.get("severity"):
            extra = f" [{node.get('severity')}]"
        return f"{glyph} {label}{extra}"

    def _print_ascii_graph(self, root_id, node_map, forward, sample_limit):
        print_info(f"ROOT {self._node_label(root_id, node_map)}")
        self._print_grouped_edges(root_id, node_map, forward, prefix="  ", sample_limit=sample_limit)

        impersonated = [
            edge.get("to")
            for edge in forward.get(root_id, [])
            if edge.get("relationship") == "can_impersonate" and edge.get("to")
        ]
        if impersonated:
            print_info("")
            print_status("Lateral movement via service accounts")
            for sa_id in impersonated:
                print_info(f"  $ {node_map.get(sa_id, {}).get('label', sa_id)}")
                self._print_grouped_edges(
                    sa_id,
                    node_map,
                    forward,
                    prefix="    ",
                    sample_limit=sample_limit,
                    allowed={"runs_as", "has_project_role"},
                )

        other_sas = [
            node_id
            for node_id, node in node_map.items()
            if node.get("type") == "service_account" and node_id not in set(impersonated)
        ]
        attached = [sa_id for sa_id in other_sas if forward.get(sa_id)]
        if attached:
            print_info("")
            print_status(f"Other service account workloads ({len(attached)})")
            for sa_id in attached[:8]:
                runs_as = [e for e in forward.get(sa_id, []) if e.get("relationship") == "runs_as"]
                if not runs_as:
                    continue
                print_info(f"  $ {node_map.get(sa_id, {}).get('label', sa_id)}")
                self._print_edge_group(
                    "runs_as",
                    runs_as,
                    node_map,
                    prefix="    ",
                    sample_limit=sample_limit,
                )
            if len(attached) > 8:
                print_info(f"  ... and {len(attached) - 8} more service account(s)")

    def _print_grouped_edges(self, node_id, node_map, forward, prefix, sample_limit, allowed=None):
        edges = forward.get(node_id, [])
        grouped = defaultdict(list)
        for edge in edges:
            rel = str(edge.get("relationship") or "link")
            if allowed and rel not in allowed:
                continue
            grouped[rel].append(edge)

        rels = sorted(grouped.keys())
        for rel_index, rel in enumerate(rels):
            is_last = rel_index == len(rels) - 1
            branch = "└── " if is_last else "├── "
            self._print_edge_group(rel, grouped[rel], node_map, prefix + branch, sample_limit, continuation_prefix=prefix)

    def _print_edge_group(self, rel, edges, node_map, prefix, sample_limit, continuation_prefix=""):
        if rel == "runs_as" and len(edges) > sample_limit:
            print_info(f"{prefix}[{rel}] x{len(edges)}")
            sub_prefix = continuation_prefix + ("    " if prefix.strip().startswith("└") else "│   ")
            for edge in edges[:sample_limit]:
                print_info(f"{sub_prefix}├── {self._node_label(edge.get('to'), node_map)}")
            remaining = len(edges) - sample_limit
            if remaining > 0:
                print_info(f"{sub_prefix}└── ... +{remaining} more")
            return

        for edge_index, edge in enumerate(edges):
            is_last = edge_index == len(edges) - 1
            if edge_index == 0:
                line_prefix = prefix
            else:
                line_prefix = continuation_prefix + ("    " if prefix.strip().startswith("└") else "│   ") + ("└── " if is_last else "├── ")
            target = edge.get("to")
            meta = edge.get("role")
            rel_text = f"[{rel}] " if edge_index == 0 else ""
            line = f"{line_prefix}{rel_text}{self._node_label(target, node_map)}"
            if meta:
                line += f" ({meta})"
            print_info(line)

    def _to_mermaid(self, graph, root_id):
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        if not nodes:
            return ""

        id_map = {}
        lines = ["flowchart TD"]
        lines.extend([
            "  classDef principal fill:#2563eb,color:#fff,stroke-width:2px;",
            "  classDef privescNode fill:#dc2626,color:#fff;",
            "  classDef saNode fill:#0891b2,color:#fff;",
            "  classDef exposureNode fill:#ea580c,color:#fff;",
            "  classDef netNode fill:#7c3aed,color:#fff;",
            "  classDef roleNode fill:#64748b,color:#fff;",
            "  classDef resourceNode fill:#334155,color:#fff;",
        ])

        class_map = {
            "principal": "principal",
            "role": "roleNode",
            "privesc_path": "privescNode",
            "service_account": "saNode",
            "public_exposure": "exposureNode",
            "network_path": "netNode",
        }

        for index, node in enumerate(nodes):
            node_id = node.get("id")
            if not node_id:
                continue
            safe = f"N{index}"
            id_map[node_id] = safe
            label = str(node.get("label") or node_id).replace('"', "'")
            if len(label) > 48:
                label = label[:45] + "..."
            lines.append(f'  {safe}["{label}"]')
            css = class_map.get(str(node.get("type") or ""), "resourceNode")
            lines.append(f"  class {safe} {css};")

        for edge in edges[:120]:
            source = id_map.get(edge.get("from"))
            target = id_map.get(edge.get("to"))
            if not source or not target:
                continue
            rel = str(edge.get("relationship") or "link").replace('"', "'")
            lines.append(f"  {source} -->|{rel}| {target}")

        if len(edges) > 120:
            lines.append(f"  %% truncated: {len(edges) - 120} additional edge(s) omitted")

        return "\n".join(lines)

    @staticmethod
    def _to_dot(graph):
        lines = [
            "digraph gcp_attack_graph {",
            '  rankdir="LR";',
            '  node [shape=box, fontsize=10];',
            '  edge [fontsize=9];',
        ]
        id_remap = {}
        for index, node in enumerate(graph.get("nodes") or []):
            node_id = str(node.get("id") or "")
            safe_id = f"N{index}"
            id_remap[node_id] = safe_id
            label = str(node.get("label") or node_id).replace('"', '\\"')
            node_type = str(node.get("type") or "")
            shape = "ellipse" if node_type == "principal" else "box"
            color = {
                "privesc_path": "red",
                "public_exposure": "orange",
                "network_path": "purple",
                "service_account": "blue",
            }.get(node_type, "black")
            lines.append(
                f'  {safe_id} [label="{label}\\n({node_type})", shape={shape}, color={color}];'
            )
        for edge in graph.get("edges") or []:
            source = id_remap.get(str(edge.get("from") or ""))
            target = id_remap.get(str(edge.get("to") or ""))
            if not source or not target:
                continue
            rel = str(edge.get("relationship") or "").replace('"', '\\"')
            lines.append(f"  {source} -> {target} [label=\"{rel}\"];")
        lines.append("}")
        return "\n".join(lines)
