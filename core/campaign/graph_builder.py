#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Build authorized attack graphs from workspace intelligence."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from core.campaign.browser_c2 import (
    BROWSER_AUX_PREFERRED,
    BROWSER_C2_TECHNIQUES,
    BROWSER_POST_TECHNIQUES,
    browser_c2_framework_commands,
    browser_server_running,
    collect_browser_sessions,
    is_browser_session,
    browser_session_host,
    browser_session_id,
)
from core.utils.service_fingerprint import PORT_SERVICE_HINTS, SERVICE_SCANNER_MODULES

MITRE_TECHNIQUE_RE = re.compile(
    r"attack\.mitre\.org/techniques/(T\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

DESTRUCTIVE_KEYWORDS = (
    "dos",
    "wipe",
    "destroy",
    "delete",
    "format",
    "ransom",
    "brick",
    "shutdown",
    "fork_bomb",
)

RISK_SCORES = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 1}

PATH_TECHNIQUE_HINTS: Tuple[Tuple[str, str], ...] = (
    ("scanner/portscan", "T1046"),
    ("scanner/discovery", "T1046"),
    ("scanner/http", "T1595.002"),
    ("scanner/ssh", "T1046"),
    ("scanner/smb", "T1046"),
    ("exploits/", "T1190"),
    ("post/", "T1059"),
    ("payloads/", "T1059"),
    ("listeners/", "T1573"),
    ("auxiliary/scanner", "T1595"),
    ("auxiliary/osint", "T1590"),
    ("auxiliary/crawler", "T1594"),
    ("browser_auxiliary/", "T1189"),
    ("browser_server", "T1071.001"),
)

RECON_MODULE_PREFERENCES: Tuple[str, ...] = (
    "auxiliary/scanner/portscan/tcp",
    "auxiliary/osint/ip_reverse_dns",
    "scanner/http/server_banner_detect",
)


@dataclass
class CampaignNode:
    """Single step in an authorized attack graph."""

    id: str
    phase: str
    title: str
    host_address: str
    host_id: Optional[int] = None
    service: Optional[Dict[str, Any]] = None
    vulnerability: Optional[Dict[str, Any]] = None
    candidate_modules: List[Dict[str, Any]] = field(default_factory=list)
    selected_module: Optional[str] = None
    module_options: Dict[str, Any] = field(default_factory=dict)
    preconditions: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    rollback_steps: List[str] = field(default_factory=list)
    risk_score: float = 1.0
    risk_level: str = "low"
    attack_techniques: List[str] = field(default_factory=list)
    scope_allowed: bool = True
    scope_reason: str = ""
    depends_on: List[str] = field(default_factory=list)
    estimated_minutes: int = 5
    dry_run_safe: bool = True
    framework_commands: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CampaignGraph:
    """Authorized attack graph for a workspace engagement."""

    workspace: str
    workspace_id: int
    generated_at: str
    scope_enforced: bool
    nodes: List[CampaignNode] = field(default_factory=list)
    edges: List[Dict[str, str]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace": self.workspace,
            "workspace_id": self.workspace_id,
            "generated_at": self.generated_at,
            "scope_enforced": self.scope_enforced,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": self.edges,
            "summary": self.summary,
        }


class CampaignGraphBuilder:
    """Transform workspace data into an authorized attack graph."""

    DEFAULT_OUTPUT_DIR = Path("artifacts") / "campaigns"

    def __init__(self, framework: Any):
        self.framework = framework

    def build(self, workspace_id: Optional[int] = None, max_steps: int = 50) -> CampaignGraph:
        snapshot = self._load_workspace_snapshot(workspace_id)
        ws_name = snapshot["workspace_name"]
        ws_id = snapshot["workspace_id"]
        scope_mgr = getattr(self.framework, "scope_manager", None)
        scope_enforced = bool(scope_mgr and scope_mgr.enabled)

        nodes: List[CampaignNode] = []
        edges: List[Dict[str, str]] = []
        host_scan_nodes: Dict[str, str] = {}
        host_web_nodes: Dict[str, str] = {}
        host_browser_c2_nodes: Dict[str, str] = {}
        used_modules: Dict[str, Set[str]] = {}

        for host in snapshot["hosts"]:
            address = host["address"]
            host_id = host.get("id")
            services = host.get("services") or []
            vulns = host.get("vulnerabilities") or []
            host_used = used_modules.setdefault(address, set())

            scope_ok, scope_reason = self._check_scope(address, scope_mgr)
            if not services:
                node = self._recon_node(host, scope_ok, scope_reason)
                nodes.append(node)
                self._track_module_use(node, host_used)
                host_scan_nodes[address] = node.id
                if len(nodes) >= max_steps:
                    break
                continue

            scan_id = host_scan_nodes.get(address)
            if not scan_id:
                scan_node = self._service_enumeration_node(host, scope_ok, scope_reason)
                nodes.append(scan_node)
                self._track_module_use(scan_node, host_used)
                host_scan_nodes[address] = scan_node.id
                scan_id = scan_node.id

            for vuln in vulns:
                if len(nodes) >= max_steps:
                    break
                exploit_node = self._vulnerability_node(
                    host, vuln, scope_ok, scope_reason, scan_id, exclude=host_used
                )
                if exploit_node:
                    nodes.append(exploit_node)
                    self._track_module_use(exploit_node, host_used)
                    edges.append({"from": scan_id, "to": exploit_node.id, "type": "enables"})

            for service in services:
                if len(nodes) >= max_steps:
                    break
                if service.get("state") not in (None, "open", "unknown"):
                    continue
                svc_node = self._service_assessment_node(
                    host, service, scope_ok, scope_reason, scan_id, exclude=host_used
                )
                if svc_node:
                    nodes.append(svc_node)
                    self._track_module_use(svc_node, host_used)
                    edges.append({"from": scan_id, "to": svc_node.id, "type": "targets"})

            if any(self._service_hint(s) in ("http", "https") for s in services):
                if len(nodes) >= max_steps:
                    break
                web_node = self._http_surface_node(
                    host, scope_ok, scope_reason, scan_id, exclude=host_used
                )
                if web_node:
                    nodes.append(web_node)
                    self._track_module_use(web_node, host_used)
                    edges.append({"from": scan_id, "to": web_node.id, "type": "web_surface"})
                    host_web_nodes[address] = web_node.id
                    if len(nodes) < max_steps:
                        browser_node = self._browser_c2_setup_node(
                            host,
                            scope_ok,
                            scope_reason,
                            web_node.id,
                            exclude=host_used,
                        )
                        if browser_node:
                            nodes.append(browser_node)
                            self._track_module_use(browser_node, host_used)
                            edges.append(
                                {"from": web_node.id, "to": browser_node.id, "type": "browser_c2"}
                            )
                            host_browser_c2_nodes[address] = browser_node.id

        browser_sessions = snapshot.get("browser_sessions") or []
        for session in snapshot.get("sessions") or []:
            if len(nodes) >= max_steps:
                break
            if is_browser_session(session):
                continue
            post_node = self._post_exploitation_node(session, scope_mgr)
            if post_node:
                nodes.append(post_node)
                parent = host_scan_nodes.get(session.get("target_host") or "")
                if parent:
                    edges.append({"from": parent, "to": post_node.id, "type": "post_session"})

        for session in browser_sessions:
            if len(nodes) >= max_steps:
                break
            browser_node = self._browser_post_exploitation_node(session, scope_mgr)
            if not browser_node:
                continue
            nodes.append(browser_node)
            target_host = browser_session_host(session)
            parent = (
                host_browser_c2_nodes.get(target_host)
                or host_web_nodes.get(target_host)
                or host_scan_nodes.get(target_host)
                or ""
            )
            if parent:
                edges.append({"from": parent, "to": browser_node.id, "type": "browser_session"})

        graph = CampaignGraph(
            workspace=ws_name,
            workspace_id=ws_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            scope_enforced=scope_enforced,
            nodes=nodes,
            edges=edges,
            summary=self._build_summary(nodes, scope_enforced, snapshot),
        )
        return graph

    def write_artifacts(
        self,
        graph: CampaignGraph,
        output_dir: Optional[str] = None,
        formats: Optional[Sequence[str]] = None,
        force: bool = False,
    ) -> Path:
        selected = set(formats or ["graph", "plan", "dry_run", "timeline", "report", "navigator"])
        slug = self._slugify(graph.workspace)
        root = Path(output_dir or self.DEFAULT_OUTPUT_DIR) / slug
        if root.exists() and any(root.iterdir()) and not force:
            raise FileExistsError(f"Campaign artifacts already exist: {root}. Use --force to overwrite.")
        root.mkdir(parents=True, exist_ok=True)

        if "graph" in selected:
            self._write_json(root / "graph.json", graph.to_dict())
        if "plan" in selected:
            self._write_json(root / "plan_executable.json", self.export_executable_plan(graph))
        if "dry_run" in selected:
            self._write_json(root / "plan_dry_run.json", self.export_dry_run_plan(graph))
        if "timeline" in selected:
            self._write_json(root / "timeline.json", self.export_timeline(graph))
        if "report" in selected:
            (root / "report.md").write_text(self.export_report(graph), encoding="utf-8")
        if "navigator" in selected:
            self._write_json(root / "attack_navigator_layer.json", self.export_attack_navigator(graph))
        return root

    def export_executable_plan(self, graph: CampaignGraph) -> Dict[str, Any]:
        steps = []
        for index, node in enumerate(graph.nodes, start=1):
            if not node.scope_allowed:
                continue
            if not node.selected_module and not node.framework_commands:
                continue
            steps.append(
                {
                    "step": index,
                    "node_id": node.id,
                    "phase": node.phase,
                    "title": node.title,
                    "host": node.host_address,
                    "module": node.selected_module,
                    "options": node.module_options,
                    "framework_commands": list(node.framework_commands),
                    "commands": self._kitty_commands(node),
                    "preconditions": node.preconditions,
                    "expected_evidence": node.expected_evidence,
                    "rollback_steps": node.rollback_steps,
                    "risk_level": node.risk_level,
                    "depends_on": node.depends_on,
                    "dry_run": False,
                }
            )
        return {
            "workspace": graph.workspace,
            "generated_at": graph.generated_at,
            "mode": "executable",
            "scope_enforced": graph.scope_enforced,
            "step_count": len(steps),
            "steps": steps,
        }

    def export_dry_run_plan(self, graph: CampaignGraph) -> Dict[str, Any]:
        plan = self.export_executable_plan(graph)
        plan["mode"] = "dry_run"
        for step in plan["steps"]:
            step["dry_run"] = True
            step["commands"] = [f"{cmd}  # dry-run" for cmd in step.get("commands", [])]
        return plan

    def export_timeline(self, graph: CampaignGraph) -> List[Dict[str, Any]]:
        cursor = datetime.now(timezone.utc)
        timeline: List[Dict[str, Any]] = []
        for node in graph.nodes:
            timeline.append(
                {
                    "time": cursor.isoformat(),
                    "node_id": node.id,
                    "phase": node.phase,
                    "title": node.title,
                    "host": node.host_address,
                    "module": node.selected_module,
                    "risk_level": node.risk_level,
                    "scope_allowed": node.scope_allowed,
                    "expected_evidence": node.expected_evidence,
                    "duration_minutes": node.estimated_minutes,
                }
            )
            cursor = cursor + timedelta(minutes=node.estimated_minutes)
        return timeline

    def export_report(self, graph: CampaignGraph) -> str:
        lines = [
            f"# Campaign Plan — {graph.workspace}",
            "",
            f"- Generated: {graph.generated_at}",
            f"- Scope enforced: {'yes' if graph.scope_enforced else 'no'}",
            f"- Steps: {len(graph.nodes)}",
            f"- In-scope steps: {graph.summary.get('in_scope_steps', 0)}",
            f"- High risk steps: {graph.summary.get('high_risk_steps', 0)}",
            "",
            "## Attack graph",
            "",
        ]
        for node in graph.nodes:
            scope_flag = "in-scope" if node.scope_allowed else "OUT OF SCOPE"
            lines.extend(
                [
                    f"### {node.title} ({node.phase})",
                    "",
                    f"- Host: `{node.host_address}`",
                    f"- Module: `{node.selected_module or 'see framework commands'}`",
                    f"- Risk: **{node.risk_level}** ({scope_flag})",
                    f"- Techniques: {', '.join(node.attack_techniques) or 'n/a'}",
                    "",
                    "**Preconditions**",
                ]
            )
            lines.extend(f"- {p}" for p in node.preconditions or ["None"])
            lines.extend(["", "**Expected evidence**"])
            lines.extend(f"- {e}" for e in node.expected_evidence or ["Operator notes"])
            lines.extend(["", "**Rollback**"])
            lines.extend(f"- {r}" for r in node.rollback_steps or ["Document state and notify stakeholders"])
            lines.extend(["", "**Commands**"])
            for cmd in self._kitty_commands(node) or ["(none)"]:
                lines.append(f"- `{cmd}`")
            lines.append("")
        if graph.edges:
            lines.extend(["## Dependencies", ""])
            for edge in graph.edges:
                lines.append(f"- `{edge['from']}` → `{edge['to']}` ({edge.get('type', 'related')})")
            lines.append("")
        lines.extend(
            [
                "## Exports",
                "",
                "- `plan_executable.json` — runnable KittySploit command sequence",
                "- `plan_dry_run.json` — same plan flagged for rehearsal",
                "- `timeline.json` — ordered schedule with evidence checkpoints",
                "- `attack_navigator_layer.json` — MITRE ATT&CK Navigator overlay",
                "",
            ]
        )
        return "\n".join(lines)

    def export_attack_navigator(self, graph: CampaignGraph) -> Dict[str, Any]:
        techniques: Dict[str, Dict[str, Any]] = {}
        for node in graph.nodes:
            if not node.scope_allowed:
                continue
            for tech in node.attack_techniques:
                entry = techniques.setdefault(
                    tech,
                    {"techniqueID": tech, "score": 0, "comment": "", "enabled": True, "metadata": []},
                )
                entry["score"] += max(1, int(node.risk_score))
                note = f"{node.title} @ {node.host_address}"
                entry["comment"] = (entry["comment"] + "; " + note).strip("; ")

        return {
            "name": f"KittySploit — {graph.workspace}",
            "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Authorized campaign graph generated {graph.generated_at}",
            "techniques": list(techniques.values()),
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 10,
            },
            "legendItems": [
                {"label": "planned action", "color": "#ff6666"},
            ],
        }

    def _load_workspace_snapshot(self, workspace_id: Optional[int]) -> Dict[str, Any]:
        wm = getattr(self.framework, "workspace_manager", None)
        db = getattr(self.framework, "db_manager", None)
        if not db or not wm:
            raise RuntimeError("Database or workspace manager unavailable")

        session = db.get_session("default")
        if not session:
            raise RuntimeError("Could not open database session")

        from core.models.models import Host

        current = wm.get_current_workspace()
        if workspace_id is None:
            if not current:
                raise RuntimeError("No active workspace")
            workspace_id = current.id
            workspace_name = current.name
        else:
            from core.models.models import Workspace

            ws = session.query(Workspace).filter(Workspace.id == workspace_id).first()
            if not ws:
                raise RuntimeError(f"Workspace id {workspace_id} not found")
            workspace_name = ws.name

        hosts_out: List[Dict[str, Any]] = []
        hosts = session.query(Host).filter(Host.workspace_id == workspace_id).all()
        for host in hosts:
            services = [s.to_dict() for s in (host.services or [])]
            vulns = [v.to_dict() for v in (host.vulnerabilities or [])]
            hosts_out.append({**host.to_dict(), "services": services, "vulnerabilities": vulns})

        sessions_out: List[Dict[str, Any]] = []
        sm = getattr(self.framework, "session_manager", None)
        if sm:
            for sess in sm.get_sessions() or []:
                sessions_out.append(
                    {
                        "id": sess.id,
                        "target_host": sess.host,
                        "host": sess.host,
                        "port": sess.port,
                        "session_type": sess.session_type,
                        **(sess.data or {}),
                    }
                )

        browser_sessions = collect_browser_sessions(self.framework)
        known_ids = {str(item.get("id") or "") for item in sessions_out}
        for row in browser_sessions:
            session_id = browser_session_id(row)
            if session_id and session_id not in known_ids:
                sessions_out.append(row)
                known_ids.add(session_id)

        return {
            "workspace_id": workspace_id,
            "workspace_name": workspace_name,
            "hosts": hosts_out,
            "sessions": sessions_out,
            "browser_sessions": browser_sessions,
            "browser_server_running": browser_server_running(self.framework),
        }

    def _check_scope(self, address: str, scope_mgr: Any) -> Tuple[bool, str]:
        if not scope_mgr or not scope_mgr.enabled:
            return True, "scope not enforced"
        decision = scope_mgr.is_target_allowed(address)
        if decision.allowed:
            return True, decision.reason or "allowed"
        return False, decision.reason or "denied by scope"

    def _recon_node(self, host: Dict[str, Any], scope_ok: bool, scope_reason: str) -> CampaignNode:
        address = host["address"]
        candidates = self._find_modules(query="discovery", module_type="scanner", limit=8)
        for path in RECON_MODULE_PREFERENCES:
            if self._module_exists(path) and not any(c["path"] == path for c in candidates):
                candidates.insert(0, {"path": path, "name": path.rsplit("/", 1)[-1], "score": 2.0})
        selected = self._pick_module_path(RECON_MODULE_PREFERENCES, candidates)
        framework_cmds = self._recon_framework_commands(address)
        options = self._module_options(selected, address) if selected else {}
        title = f"Initial reconnaissance on {address}"
        if selected == "auxiliary/scanner/portscan/tcp":
            title = f"TCP port discovery on {address}"
        elif selected == "auxiliary/osint/ip_reverse_dns":
            title = f"Passive DNS recon on {address}"
        return CampaignNode(
            id=self._node_id("recon"),
            phase="recon",
            title=title,
            host_address=address,
            host_id=host.get("id"),
            candidate_modules=candidates,
            selected_module=selected,
            module_options=options,
            framework_commands=framework_cmds,
            preconditions=[
                f"Host {address} is authorized in engagement scope",
                "Written authorization for active scanning is on file",
            ],
            expected_evidence=[
                "PTR / hostname mapping if available",
                "Open port list from network_discover or scanner",
                "Service banners where available",
            ],
            rollback_steps=["No host changes expected; archive raw scanner output"],
            risk_score=2.0,
            risk_level="low",
            attack_techniques=self._techniques_for_module(selected or "scanner/http"),
            scope_allowed=scope_ok,
            scope_reason=scope_reason,
            estimated_minutes=15,
            dry_run_safe=True,
        )

    def _service_enumeration_node(
        self, host: Dict[str, Any], scope_ok: bool, scope_reason: str
    ) -> CampaignNode:
        address = host["address"]
        services = host.get("services") or []
        hints = sorted({self._service_hint(s) for s in services if self._service_hint(s)})
        query = hints[0] if hints else "http"
        scheme = "https" if query == "https" else "http"
        return CampaignNode(
            id=self._node_id("enum"),
            phase="enumeration",
            title=f"Broad scanner sweep on {address}",
            host_address=address,
            host_id=host.get("id"),
            candidate_modules=[],
            selected_module=None,
            module_options={},
            framework_commands=[f"scanner -u {scheme}://{address} --scan-ports"],
            preconditions=[f"Host {address} reachable", "Scope allows active scanning"],
            expected_evidence=["Open services", "Technology fingerprints", "Scanner findings"],
            rollback_steps=["Stop active checks", "Retain scan logs only"],
            risk_score=2.5,
            risk_level="low",
            attack_techniques=["T1595"],
            scope_allowed=scope_ok,
            scope_reason=scope_reason,
            estimated_minutes=10,
        )

    def _vulnerability_node(
        self,
        host: Dict[str, Any],
        vuln: Dict[str, Any],
        scope_ok: bool,
        scope_reason: str,
        depends_on: str,
        exclude: Optional[Set[str]] = None,
    ) -> Optional[CampaignNode]:
        address = host["address"]
        cve = (vuln.get("cve") or "").strip()
        name = vuln.get("name") or "finding"
        candidates = []
        if cve:
            candidates = self._find_modules(cve=cve, limit=10)
        if not candidates:
            candidates = self._find_modules(query=name.split()[0], module_type="exploits", limit=5)
        if not candidates:
            candidates = self._find_modules(query=name.split()[0], module_type="auxiliary", limit=5)
        if not candidates:
            return None

        selected = self._pick_module_path((), candidates, exclude=exclude)
        if not selected:
            return None
        risk_level = vuln.get("risk_level") or "medium"
        risk_score = float(RISK_SCORES.get(risk_level, 3))
        if "/exploits/" in selected:
            risk_score = max(risk_score, 4.0)
        destructive = any(k in selected.lower() for k in DESTRUCTIVE_KEYWORDS)
        if destructive:
            risk_level = "critical"
            risk_score = 5.0

        options = self._module_options(selected, address, vuln=vuln)

        return CampaignNode(
            id=self._node_id("vuln"),
            phase="exploitation" if "/exploits/" in selected else "validation",
            title=f"Address {name} on {address}",
            host_address=address,
            host_id=host.get("id"),
            vulnerability=vuln,
            candidate_modules=candidates,
            selected_module=selected,
            module_options=options,
            preconditions=[
                f"Vulnerability recorded: {name}",
                f"CVE: {cve}" if cve else "Validated finding in workspace",
                "Exploit attempt explicitly authorized",
            ],
            expected_evidence=[
                "Successful check or controlled proof",
                "Session or artifact captured in loot",
                "Timestamped operator notes",
            ],
            rollback_steps=[
                "Terminate spawned sessions",
                "Remove persistence if introduced",
                "Restore altered data from backup where applicable",
                "Record evidence hash for chain of custody",
            ],
            risk_score=risk_score,
            risk_level=risk_level if not destructive else "critical",
            attack_techniques=self._techniques_for_module(
                selected,
                next((c for c in candidates if c.get("path") == selected), None),
            ),
            scope_allowed=scope_ok,
            scope_reason=scope_reason,
            depends_on=[depends_on],
            estimated_minutes=20,
            dry_run_safe="/exploits/" not in selected,
        )

    def _service_assessment_node(
        self,
        host: Dict[str, Any],
        service: Dict[str, Any],
        scope_ok: bool,
        scope_reason: str,
        depends_on: str,
        exclude: Optional[Set[str]] = None,
    ) -> Optional[CampaignNode]:
        address = host["address"]
        hint = self._service_hint(service)
        if not hint:
            return None
        preferred = (SERVICE_SCANNER_MODULES.get(hint),) if hint in SERVICE_SCANNER_MODULES else ()
        candidates = self._find_modules(query=hint, module_type="scanner", limit=6)
        if not candidates:
            candidates = self._find_modules(query=hint, module_type="auxiliary", limit=6)
        selected = self._pick_module_path(preferred, candidates, exclude=exclude)
        if not selected:
            return None
        port = service.get("port")
        return CampaignNode(
            id=self._node_id("svc"),
            phase="assessment",
            title=f"Assess {hint} on {address}:{port or '?'}",
            host_address=address,
            host_id=host.get("id"),
            service=service,
            candidate_modules=candidates,
            selected_module=selected,
            module_options=self._module_options(selected, address, service=service),
            framework_commands=[],
            preconditions=[f"Service {hint} observed open on {address}"],
            expected_evidence=["Scanner module output", "Confirmed or ruled-out weaknesses"],
            rollback_steps=["No persistence expected for scanner modules"],
            risk_score=2.5,
            risk_level="low",
            attack_techniques=self._techniques_for_module(
                selected or f"scanner/{hint}",
                candidates[0] if candidates else None,
            ),
            scope_allowed=scope_ok,
            scope_reason=scope_reason,
            depends_on=[depends_on],
            estimated_minutes=8,
        )

    def _http_surface_node(
        self,
        host: Dict[str, Any],
        scope_ok: bool,
        scope_reason: str,
        depends_on: str,
        exclude: Optional[Set[str]] = None,
    ) -> Optional[CampaignNode]:
        address = host["address"]
        preferred = (
            "auxiliary/scanner/http/robots",
            "auxiliary/scanner/http/crawler",
            "auxiliary/scanner/http/login_page_detector",
        )
        candidates = self._find_modules(query="http", module_type="auxiliary", limit=10)
        selected = self._pick_module_path(preferred, candidates, exclude=exclude)
        if not selected:
            return None
        return CampaignNode(
            id=self._node_id("web"),
            phase="enumeration",
            title=f"HTTP surface mapping on {address}",
            host_address=address,
            host_id=host.get("id"),
            candidate_modules=candidates,
            selected_module=selected,
            module_options=self._module_options(selected, address),
            framework_commands=[],
            preconditions=["HTTP service discovered on target"],
            expected_evidence=["robots.txt paths", "crawlable endpoints", "login surfaces"],
            rollback_steps=["No persistence expected for passive HTTP checks"],
            risk_score=2.0,
            risk_level="low",
            attack_techniques=self._techniques_for_module(selected),
            scope_allowed=scope_ok,
            scope_reason=scope_reason,
            depends_on=[depends_on],
            estimated_minutes=12,
            dry_run_safe=True,
        )

    def _browser_c2_setup_node(
        self,
        host: Dict[str, Any],
        scope_ok: bool,
        scope_reason: str,
        depends_on: str,
        exclude: Optional[Set[str]] = None,
    ) -> Optional[CampaignNode]:
        address = host["address"]
        candidates = self._find_modules(query="browser", module_type="browser_auxiliary", limit=8)
        selected = self._pick_module_path(BROWSER_AUX_PREFERRED, candidates, exclude=exclude)
        endpoints = browser_c2_framework_commands(self.framework, host_address=address)
        return CampaignNode(
            id=self._node_id("browser_c2"),
            phase="c2",
            title=f"Browser C2 (`browser_server`) on {address}",
            host_address=address,
            host_id=host.get("id"),
            candidate_modules=candidates,
            selected_module=selected,
            module_options=self._browser_module_options(selected, address),
            framework_commands=endpoints,
            preconditions=[
                "Authorized client-side / browser testing in scope",
                "Victim browser can reach the operator browser_server endpoint",
            ],
            expected_evidence=[
                "browser_server status reports running listener",
                "Hook script delivered (inject.js / xss.js)",
                "Active browser session listed in browser_server sessions",
            ],
            rollback_steps=[
                "browser_server stop",
                "Remove injected script from test pages used during the engagement",
            ],
            risk_score=3.0,
            risk_level="medium",
            attack_techniques=list(BROWSER_C2_TECHNIQUES),
            scope_allowed=scope_ok,
            scope_reason=scope_reason,
            depends_on=[depends_on],
            estimated_minutes=20,
            dry_run_safe=True,
        )

    def _browser_post_exploitation_node(
        self, session: Dict[str, Any], scope_mgr: Any
    ) -> Optional[CampaignNode]:
        target = browser_session_host(session)
        session_id = browser_session_id(session)
        if not session_id:
            return None
        scope_ok, scope_reason = self._check_scope(str(target), scope_mgr)
        candidates = self._find_modules(query="browser", module_type="browser_auxiliary", limit=8)
        selected = self._pick_module_path(BROWSER_AUX_PREFERRED, candidates)
        if not selected and candidates:
            selected = candidates[0]["path"]
        if not selected:
            selected = BROWSER_AUX_PREFERRED[0]
        short_id = session_id[:8]
        framework_cmds = [
            "browser_server sessions",
            f"use {selected}",
            f"set SESSION {session_id}",
            "run --preview",
        ]
        return CampaignNode(
            id=self._node_id("browser_post"),
            phase="post_exploitation",
            title=f"Browser operator actions on session {short_id}",
            host_address=str(target),
            candidate_modules=candidates,
            selected_module=selected,
            module_options={"SESSION": session_id},
            framework_commands=framework_cmds,
            preconditions=[
                "browser_server is running",
                f"Active browser session {session_id} is polling",
            ],
            expected_evidence=[
                "Browser auxiliary module output stored in workspace/session context",
                "Captured DOM / fingerprint / operator telemetry as applicable",
            ],
            rollback_steps=[
                "Stop active browser auxiliary modules",
                "Close or invalidate browser session when testing is complete",
            ],
            risk_score=3.0,
            risk_level="medium",
            attack_techniques=list(BROWSER_POST_TECHNIQUES),
            scope_allowed=scope_ok,
            scope_reason=scope_reason,
            estimated_minutes=10,
            dry_run_safe=True,
        )

    def _browser_module_options(self, module_path: Optional[str], address: str) -> Dict[str, Any]:
        if not module_path:
            return {}
        return {"SESSION": "", "target": address}

    def _post_exploitation_node(self, session: Dict[str, Any], scope_mgr: Any) -> Optional[CampaignNode]:
        target = (
            session.get("target_host")
            or session.get("session_host")
            or session.get("host")
            or "session"
        )
        scope_ok, scope_reason = self._check_scope(str(target), scope_mgr)
        candidates = self._find_modules(query="gather", module_type="post", limit=6)
        if not candidates:
            return None
        selected = candidates[0]["path"]
        return CampaignNode(
            id=self._node_id("post"),
            phase="post_exploitation",
            title=f"Post-exploitation on session {session.get('id', '?')}",
            host_address=str(target),
            candidate_modules=candidates,
            selected_module=selected,
            module_options={"SESSION": session.get("id", "")},
            preconditions=["Active shell session in workspace", "Post-ex actions authorized"],
            expected_evidence=["Collected artifacts stored in loot", "Credential findings tagged to host"],
            rollback_steps=["Close session when collection complete", "Purge staged files from target if policy requires"],
            risk_score=3.5,
            risk_level="medium",
            attack_techniques=self._techniques_for_module(
                selected,
                next((c for c in candidates if c.get("path") == selected), None),
            ),
            scope_allowed=scope_ok,
            scope_reason=scope_reason,
            estimated_minutes=15,
            dry_run_safe=False,
        )

    def _find_modules(
        self,
        query: str = "",
        module_type: str = "",
        cve: str = "",
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        loader = getattr(self.framework, "module_loader", None)
        if not loader:
            return []
        rows = loader.search_modules_db(
            query=query,
            module_type=module_type,
            cve=cve,
            limit=limit,
        )
        out: List[Dict[str, Any]] = []
        for row in rows:
            path = row.get("path") or row.get("module_path") or ""
            if not path:
                continue
            score = self._module_score(path, row, cve=cve, query=query)
            out.append(
                {
                    "path": path,
                    "name": row.get("name") or path,
                    "type": row.get("type") or row.get("module_type") or "",
                    "cve": row.get("cve") or "",
                    "tags": row.get("tags") or [],
                    "score": round(score, 2),
                }
            )
        out.sort(key=lambda x: x["score"], reverse=True)
        return [row for row in out if self._module_exists(row["path"])]

    def _module_exists(self, module_path: Optional[str]) -> bool:
        if not module_path:
            return False
        loader = getattr(self.framework, "module_loader", None)
        if not loader:
            return False
        try:
            discovered = loader.discover_modules()
            if module_path in discovered:
                return True
        except Exception:
            pass
        try:
            row = loader.get_module_by_path_db(module_path)
            return bool(row)
        except Exception:
            return False

    def _pick_module_path(
        self,
        preferred: Sequence[str],
        candidates: Sequence[Dict[str, Any]],
        exclude: Optional[Set[str]] = None,
    ) -> Optional[str]:
        blocked = exclude or set()
        for path in preferred:
            if path and path not in blocked and self._module_exists(path):
                return path
        for row in candidates:
            path = row.get("path")
            if path and path not in blocked and self._module_exists(path):
                return path
        return None

    def _track_module_use(self, node: CampaignNode, used: Set[str]) -> None:
        if node.selected_module:
            used.add(node.selected_module)

    def _recon_framework_commands(self, address: str) -> List[str]:
        return [
            f"network_discover --range {address}/32 --method ping",
            f"scanner -u http://{address} --scan-ports",
        ]

    def _module_options(
        self,
        module_path: Optional[str],
        address: str,
        service: Optional[Dict[str, Any]] = None,
        vuln: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not module_path:
            return {}
        port = (service or {}).get("port")
        if module_path == "auxiliary/osint/ip_reverse_dns":
            return {"target": address}
        if module_path == "auxiliary/scanner/portscan/tcp":
            return {"rhosts": address, "ports": "1-10000", "threads": 10}
        if module_path.startswith(("scanner/", "auxiliary/scanner/")):
            opts: Dict[str, Any] = {"target": address}
            if port:
                opts["port"] = port
            elif "http" in module_path:
                opts["port"] = 443 if "https" in (self._service_hint(service) if service else "") else 80
            return opts
        opts = {"RHOSTS": address}
        if port:
            opts["RPORT"] = port
        if vuln and vuln.get("service_id"):
            opts.setdefault("TARGETURI", "/")
        return opts

    def _module_score(self, path: str, row: Dict[str, Any], cve: str = "", query: str = "") -> float:
        score = 1.0
        row_cve = (row.get("cve") or "").upper()
        if cve and row_cve == cve.upper():
            score += 5.0
        if query and query.lower() in path.lower():
            score += 2.0
        if "/exploits/" in path:
            score += 1.0
        if any(k in path.lower() for k in DESTRUCTIVE_KEYWORDS):
            score -= 3.0
        return score

    def _service_hint(self, service: Dict[str, Any]) -> str:
        name = (service.get("name") or "").lower()
        port = service.get("port")
        if name and name not in ("unknown", "tcp", "udp"):
            return name.split("-")[0].split("_")[0]
        if port in PORT_SERVICE_HINTS:
            return PORT_SERVICE_HINTS[port]
        return ""

    def _techniques_for_module(self, module_path: Optional[str], row: Optional[Dict[str, Any]] = None) -> List[str]:
        if not module_path:
            return ["T1595"]
        found: List[str] = []
        refs = (row or {}).get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        for ref in refs:
            match = MITRE_TECHNIQUE_RE.search(str(ref))
            if match:
                found.append(match.group(1).upper())
        lowered = module_path.lower()
        for fragment, tech in PATH_TECHNIQUE_HINTS:
            if fragment in lowered and tech not in found:
                found.append(tech)
        return found or ["T1595"]

    def _kitty_commands(self, node: CampaignNode) -> List[str]:
        cmds: List[str] = []
        if node.selected_module and self._module_exists(node.selected_module):
            cmds.append(f"use {node.selected_module}")
            for key, value in sorted(node.module_options.items()):
                cmds.append(f"set {key} {value}")
            cmds.append("run --preview" if node.dry_run_safe else "run")
        cmds.extend(node.framework_commands)
        return cmds

    def _build_summary(
        self,
        nodes: List[CampaignNode],
        scope_enforced: bool,
        snapshot: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        phases: Dict[str, int] = {}
        techniques: List[str] = []
        for node in nodes:
            phases[node.phase] = phases.get(node.phase, 0) + 1
            techniques.extend(node.attack_techniques)
        in_scope = sum(1 for n in nodes if n.scope_allowed)
        high_risk = sum(1 for n in nodes if n.risk_level in ("high", "critical"))
        hosts = snapshot.get("hosts") if snapshot else []
        service_count = sum(len(h.get("services") or []) for h in hosts)
        browser_sessions = (snapshot or {}).get("browser_sessions") or []
        return {
            "total_steps": len(nodes),
            "in_scope_steps": in_scope,
            "out_of_scope_steps": len(nodes) - in_scope,
            "high_risk_steps": high_risk,
            "workspace_hosts": len(hosts),
            "workspace_services": service_count,
            "browser_sessions": len(browser_sessions),
            "browser_server_running": bool((snapshot or {}).get("browser_server_running")),
            "phases": phases,
            "techniques": sorted(set(techniques)),
            "scope_enforced": scope_enforced,
        }

    def _node_id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:8]}"

    def _slugify(self, value: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", (value or "default").strip().lower())
        return slug.strip("-") or "default"

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
