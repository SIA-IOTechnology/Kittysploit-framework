#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Goal-oriented planning defaults for agent campaigns."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

GOAL_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "recon": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["dry_run_complete", "no_vulnerabilities"],
        "default_budget": 20,
        "skip_exploitation": True,
    },
    "validate": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["no_vulnerabilities"],
        "default_budget": 15,
        "skip_exploitation": True,
    },
    "obtain-auth": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["shell_obtained"],
        "default_budget": 25,
        "skip_exploitation": False,
    },
    "obtain-shell": {
        "allowed_action_types": ["prioritize", "run_followup", "run_exploit"],
        "terminal_conditions": ["shell_obtained"],
        "default_budget": 40,
        "skip_exploitation": False,
    },
    "post-auth": {
        "allowed_action_types": ["prioritize", "run_followup", "run_exploit"],
        "terminal_conditions": ["shell_obtained"],
        "default_budget": 35,
        "skip_exploitation": False,
    },
    "evidence-only": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["dry_run_complete"],
        "default_budget": 12,
        "skip_exploitation": True,
    },
    "detection-validation": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["waf_or_blocking_detected"],
        "default_budget": 18,
        "skip_exploitation": True,
    },
    "retest": {
        "allowed_action_types": ["run_followup"],
        "terminal_conditions": ["no_vulnerabilities"],
        "default_budget": 8,
        "skip_exploitation": True,
    },
    "infra-discovery": {
        "allowed_action_types": ["prioritize", "run_followup"],
        "terminal_conditions": ["dry_run_complete", "no_vulnerabilities"],
        "default_budget": 70,
        "skip_exploitation": True,
        "suggested_workflows": [
            "network-services",
            "devops-panels",
            "saas-panels",
            "verification",
            "service-discovery",
        ],
    },
}


def normalize_goal(goal: Optional[str]) -> str:
    value = str(goal or "recon").strip().lower().replace("_", "-")
    aliases = {
        "obtain_auth": "obtain-auth",
        "obtain_shell": "obtain-shell",
        "post_auth": "post-auth",
        "evidence_only": "evidence-only",
        "detection_validation": "detection-validation",
    }
    return aliases.get(value, value)


SHELL_OPERATOR_GOALS = frozenset({"obtain-shell"})
EXPLOIT_OPERATOR_GOALS = frozenset({"obtain-shell", "post-auth"})


def is_shell_operator_goal(goal: Optional[str]) -> bool:
    return normalize_goal(goal) in SHELL_OPERATOR_GOALS


def is_exploit_operator_goal(goal: Optional[str]) -> bool:
    return normalize_goal(goal) in EXPLOIT_OPERATOR_GOALS


def operator_goal_from_mapping(mapping: Any) -> str:
    """Read normalized operator goal from state dict or knowledge base."""
    if not isinstance(mapping, dict):
        return ""
    raw = (
        mapping.get("operator_goal")
        or mapping.get("operator_campaign_goal")
        or mapping.get("campaign_goal")
        or ""
    )
    return normalize_goal(str(raw).strip() or None) if str(raw).strip() else ""


def _module_observed_in_kb(kb: Mapping[str, Any], *needles: str) -> bool:
    observed = [str(p).lower() for p in (kb.get("observed_modules") or []) if p]
    return any(any(n in p for n in needles) for p in observed)


def kb_client_js_surface_ready(kb: Mapping[str, Any]) -> bool:
    """True when client-side JS / source-map analysis is warranted."""
    if not isinstance(kb, Mapping):
        return False
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if signals.intersection({
        "api_surface_detected",
        "graphql_surface_detected",
        "active_web_probe_completed",
        "test_api_surface",
    }):
        return True
    hints = {str(h).lower() for h in kb.get("tech_hints", []) or []}
    if hints.intersection({"nextjs", "nodejs", "react", "javascript", "angular", "vue", "api"}):
        return True
    endpoints = [str(e).lower() for e in kb.get("discovered_endpoints", []) or []]
    if any(".js" in e or "/_next/" in e or "/static/" in e for e in endpoints):
        return True
    request_intel = kb.get("request_intel") or {}
    for row in (request_intel.get("interesting_requests") or [])[:16]:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("path") or "").lower()
        ctype = str(row.get("content_type") or "").lower()
        if ".js" in url or "javascript" in ctype or "/static/" in url:
            return True
    return kb_api_surface_ready(kb)


def kb_api_surface_ready(kb: Mapping[str, Any]) -> bool:
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if signals.intersection({"api_surface_detected", "test_api_surface", "api_surface_from_osint", "active_web_probe_completed"}):
        return True
    request_intel = kb.get("request_intel") or {}
    if any(
        any(tok in " ".join(str(r) for r in (row.get("reasons") or [])).lower() for tok in ("api", "graphql", "swagger"))
        for row in (request_intel.get("interesting_requests") or [])[:12]
        if isinstance(row, dict)
    ):
        return True
    conf = kb.get("tech_confidence", {}) or {}
    if float(conf.get("api", 0.0) or 0.0) >= 0.45:
        return True
    endpoints = kb.get("discovered_endpoints", []) or []
    return any(
        any(token in str(endpoint).lower() for token in ("/api", "swagger", "graphql", "openapi"))
        for endpoint in endpoints
    )


def _normalize_subdomain_host(host: Any) -> str:
    return str(host or "").lower().strip(".")


def kb_subdomain_candidate_hosts(kb: Mapping[str, Any]) -> List[str]:
    """Deduped subdomain/derived hostnames known from OSINT and KB harvest."""
    if not isinstance(kb, dict):
        return []
    seed_l = _normalize_subdomain_host(kb.get("target_hostname") or kb.get("seed_hostname") or "")
    seen: set = set()
    out: List[str] = []

    def _add(raw: Any) -> None:
        host = _normalize_subdomain_host(raw)
        if not host or host in seen:
            return
        if seed_l and host == seed_l:
            return
        seen.add(host)
        out.append(host)

    for raw in kb.get("subdomain_candidates") or []:
        _add(raw)
    for raw in kb.get("derived_target_candidates") or []:
        _add(raw)

    graph = kb.get("osint_graph") or {}
    nodes = graph.get("nodes") if isinstance(graph, dict) else []
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        if str(node.get("type", "") or "").lower() != "subdomain":
            continue
        _add(node.get("hostname") or node.get("host") or node.get("id") or node.get("name") or node.get("label"))

    return out


def kb_scanned_derived_hosts(kb: Mapping[str, Any]) -> set:
    """Hosts already covered by ``derived_host_scans`` records."""
    scanned: set = set()
    if not isinstance(kb, dict):
        return scanned
    for row in kb.get("derived_host_scans") or []:
        if isinstance(row, dict):
            host = _normalize_subdomain_host(row.get("host") or row.get("hostname"))
        else:
            host = _normalize_subdomain_host(row)
        if host:
            scanned.add(host)
    return scanned


def kb_unscanned_subdomain_hosts(kb: Mapping[str, Any]) -> List[str]:
    """Candidate hosts not yet present in ``derived_host_scans``."""
    candidates = kb_subdomain_candidate_hosts(kb)
    scanned = kb_scanned_derived_hosts(kb)
    return [host for host in candidates if host not in scanned]


def kb_subdomain_surface_expandable(kb: Mapping[str, Any]) -> bool:
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if "expand_host_surface" in signals:
        return True

    unscanned = kb_unscanned_subdomain_hosts(kb)
    if unscanned:
        return True

    if kb.get("subdomain_candidates") or kb_subdomain_candidate_hosts(kb):
        return False

    return not _module_observed_in_kb(kb, "domain_surface_mapper", "domain_crtsh")


SHELL_API_MODULE_LADDER: Sequence[tuple[str, str]] = (
    ("scanner/http/swagger_detect", "swagger_detect"),
    ("scanner/http/graphql_detect", "graphql_detect"),
    ("auxiliary/osint/js_sourcemap_analyzer", "js_sourcemap"),
    ("auxiliary/osint/js_endpoint_extractor", "js_endpoint"),
    ("auxiliary/scanner/http/api_fuzzer", "api_fuzzer"),
)

SHELL_INJECTION_MODULE_LADDER: Sequence[tuple[str, str]] = (
    ("auxiliary/scanner/http/lfi_fuzzer", "lfi_fuzzer"),
    ("auxiliary/scanner/http/sqli_engine", "sqli_engine"),
    ("post/http/sqli_shell", "sqli_shell"),
    ("auxiliary/scanner/http/ssrf_scanner", "ssrf_scanner"),
    ("auxiliary/scanner/http/xxe_scanner", "xxe_scanner"),
    ("auxiliary/scanner/http/php_injection", "php_injection"),
)


def score_subdomain_host(hostname: str) -> int:
    """Higher score → prioritize for derived-host HTTP scans."""
    h = str(hostname or "").lower().strip(".")
    if not h:
        return 0
    best = 0
    try:
        from interfaces.command_system.builtin.agent.agent_constants import SUBDOMAIN_PRIORITY_MARKERS
        markers = SUBDOMAIN_PRIORITY_MARKERS
    except Exception:
        markers = (
            ("api.", 40), ("admin.", 35), ("dev.", 30), ("staging.", 30),
            ("login.", 25), ("auth.", 25),
        )
    for prefix, pts in markers:
        if h.startswith(prefix):
            best = max(best, int(pts))
    dotted = f".{h}."
    for token, pts in (
        ("api", 25), ("admin", 22), ("dev", 18), ("staging", 18),
        ("stage", 16), ("login", 15), ("auth", 14), ("portal", 12),
    ):
        if h.startswith(f"{token}.") or f".{token}." in dotted:
            best = max(best, int(pts))
    return best


def prioritize_subdomain_hosts(hosts: Sequence[str]) -> List[str]:
    """Dedupe and sort subdomain candidates by shell-relevant priority."""
    ordered: List[str] = []
    seen: set = set()
    for host in hosts or []:
        hl = str(host).lower().strip(".")
        if not hl or hl in seen:
            continue
        seen.add(hl)
        ordered.append(hl)
    return sorted(ordered, key=lambda row: (-score_subdomain_host(row), row))


def suggest_shell_plan_followups(kb: Mapping[str, Any]) -> List[str]:
    """
    Ordered module paths that widen surface toward RCE/shell (used by planner + execution plan).
    Skips modules already present in ``observed_modules``.
    """
    if not isinstance(kb, dict):
        return []
    out: List[str] = []
    seen_paths: set = set()

    def _add(path: str) -> None:
        if path and path not in seen_paths:
            seen_paths.add(path)
            out.append(path)

    if kb_api_surface_ready(kb) or kb_client_js_surface_ready(kb):
        hints_blob = " ".join(str(h).lower() for h in kb.get("tech_hints", []) or [])
        ladder: List[tuple[str, str]] = list(SHELL_API_MODULE_LADDER)
        js_first = kb_client_js_surface_ready(kb) or any(
            t in hints_blob for t in ("nextjs", "nodejs", "react", "javascript")
        )
        if js_first:
            js_rows = [row for row in ladder if row[1] in ("js_sourcemap", "js_endpoint")]
            rest = [row for row in ladder if row[1] not in ("js_sourcemap", "js_endpoint")]
            ladder = js_rows + rest
        for path, needle in ladder:
            if not _module_observed_in_kb(kb, needle):
                _add(path)
                if needle in ("js_sourcemap", "js_endpoint"):
                    continue
                break

    if kb_subdomain_surface_expandable(kb) and not _module_observed_in_kb(kb, "domain_surface_mapper", "domain_crtsh"):
        _add("auxiliary/osint/domain_surface_mapper")

    endpoint_count = len(kb.get("discovered_endpoints", []) or [])
    if endpoint_count < 12 and not _module_observed_in_kb(kb, "crawler"):
        _add("auxiliary/scanner/http/crawler")

    hints = [str(h).lower() for h in kb.get("tech_hints", []) or []]
    hints_blob = " ".join(hints)
    if any(h in hints_blob for h in ("nextjs", "nodejs", "react")) and not _module_observed_in_kb(kb, "nodejs_injection"):
        _add("auxiliary/scanner/http/nodejs_injection")

    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    for path, needle in SHELL_INJECTION_MODULE_LADDER:
        short = needle.replace("_fuzzer", "").replace("_scanner", "")
        if (
            short in hints_blob
            or any(short.replace("_", "") in s for s in signals)
            or is_shell_operator_goal(kb.get("operator_campaign_goal"))
        ) and not _module_observed_in_kb(kb, needle):
            _add(path)

    request_intel = kb.get("request_intel") or {}
    for row in (request_intel.get("interesting_requests") or [])[:8]:
        if not isinstance(row, dict):
            continue
        reasons = " ".join(str(r) for r in row.get("reasons", []) or []).lower()
        if "upload surface" in reasons and not _module_observed_in_kb(kb, "php_injection"):
            _add("auxiliary/scanner/http/php_injection")
        if "file/path parameter" in reasons and not _module_observed_in_kb(kb, "lfi"):
            _add("auxiliary/scanner/http/lfi_fuzzer")

    return out


def build_goal_plan(goal: Optional[str], *, request_budget: int = 0) -> Dict[str, Any]:
    key = normalize_goal(goal)
    if key not in GOAL_DEFINITIONS:
        raise ValueError(f"Unknown campaign goal: {goal}")
    definition = GOAL_DEFINITIONS[key]
    budget = int(request_budget or definition.get("default_budget", 20))
    return {
        "campaign_goal": key,
        "next_actions": [],
        "max_requests_next_phase": budget,
        "stop_conditions": list(definition.get("terminal_conditions", [])),
        "reasoning_confidence": 0.0,
        "skip_exploitation": bool(definition.get("skip_exploitation", False)),
        "allowed_action_types": list(definition.get("allowed_action_types", [])),
    }


def filter_actions_for_goal(
    actions: List[Dict[str, Any]],
    goal: Optional[str],
) -> List[Dict[str, Any]]:
    key = normalize_goal(goal)
    definition = GOAL_DEFINITIONS.get(key, {})
    allowed = set(definition.get("allowed_action_types", []))
    if not allowed:
        return actions
    return [
        row for row in actions
        if str(row.get("type", "")).lower() in allowed
    ]
