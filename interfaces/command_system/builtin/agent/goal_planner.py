#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Goal-oriented planning defaults for agent campaigns."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

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
        "allowed_action_types": ["prioritize", "run_followup", "run_exploit"],
        "terminal_conditions": [
            "auth_obtained",
            "authenticated_session",
            "credentials_obtained",
        ],
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
        "allowed_action_types": ["prioritize", "run_followup", "run_exploit", "run_post"],
        "terminal_conditions": ["shell_obtained"],
        "default_budget": 35,
        "skip_exploitation": False,
    },
    # Tactical goal set by _sync_campaign_goal when findings warrant exploitation.
    "exploit": {
        "allowed_action_types": ["prioritize", "run_followup", "run_exploit"],
        "terminal_conditions": ["shell_obtained", "no_vulnerabilities"],
        "default_budget": 30,
        "skip_exploitation": False,
    },
    # Milestone stop goal when a shell/session was already obtained.
    "shell-obtained": {
        "allowed_action_types": ["prioritize", "run_post"],
        "terminal_conditions": ["shell_obtained"],
        "default_budget": 10,
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
        "shell_obtained": "shell-obtained",
        "shell-stop": "shell-obtained",
        "campaign_exploit": "exploit",
    }
    return aliases.get(value, value)


SHELL_OPERATOR_GOALS = frozenset({"obtain-shell"})
AUTH_OPERATOR_GOALS = frozenset({"obtain-auth"})
EXPLOIT_OPERATOR_GOALS = frozenset({"obtain-shell", "post-auth", "obtain-auth", "exploit"})
DRUPAL_CVE_2014_3704_SQLI_MODULE = "exploits/multi/http/drupal_cve_2014_3704_sqli"
DRUPAL_DRUPALGEDDON2_MODULE = "exploits/http/drupal_rce"
ADMIN_LOGIN_BRUTEFORCE_MODULE = "auxiliary/scanner/http/login/admin_login_bruteforce"
DVWA_SQLI_SHELL_MODULE = "auxiliary/scanner/http/dvwa_sqli_shell"
DVWA_RCE_MODULE = "exploits/ctf/dvwa_rce"
DVWA_FILE_UPLOAD_MODULE = "exploits/ctf/dvwa_file_upload"

# Lab/product chains that must beat metadata CVE noise when the stack is known.
# Order matters for obtain-shell: auth → OS RCE/webshell first; SQLi REPL is optional last.
_PRODUCT_SHELL_CHAINS: Dict[str, Tuple[str, ...]] = {
    "dvwa": (
        ADMIN_LOGIN_BRUTEFORCE_MODULE,
        DVWA_RCE_MODULE,
        DVWA_FILE_UPLOAD_MODULE,
        DVWA_SQLI_SHELL_MODULE,
    ),
}
SHELL_CAPABILITY_NAMES = frozenset({"shell", "rce", "session", "interactive_shell"})
AUTH_TERMINAL_SIGNALS = frozenset({
    "authenticated_session",
    "credentials_obtained",
    "auth_obtained",
})

# Lab apps with a known auth→OS-shell ladder. While this focus is active, unrelated
# CMS/plugin CVE spray is deferred (product-first, then backtrack).
_LAB_PRODUCT_FOCUS = frozenset({"dvwa", "mutillidae", "bwapp", "webgoat", "juiceshop"})
_FOREIGN_CMS_PATH_TOKENS = (
    "wordpress",
    "wp_",
    "wp-",
    "wpvivid",
    "wp_plugin",
    "drupal",
    "joomla",
    "ninja_forms",
    "blocksy",
    "balbooa",
    "elementor",
    "woocommerce",
    "wpforms",
    "gravityforms",
)


def focused_lab_product(kb: Mapping[str, Any]) -> str:
    """Dominant lab product with confidence, or empty when focus should lift."""
    if not isinstance(kb, Mapping):
        return ""
    try:
        from interfaces.command_system.builtin.agent.module_performance_memory import (
            dominant_product_stack,
        )
    except Exception:
        return ""
    dominant = str(dominant_product_stack(dict(kb), threshold=0.45) or "").lower()
    if dominant not in _LAB_PRODUCT_FOCUS:
        return ""
    signals = {str(s).lower() for s in (kb.get("risk_signals") or [])}
    if signals.intersection({"interactive_shell", "shell_obtained"}):
        return ""
    return dominant


def product_shell_chain_paths(product: str, *, include_sqli_shell: bool = False) -> Tuple[str, ...]:
    paths = _PRODUCT_SHELL_CHAINS.get(str(product or "").lower(), ())
    if include_sqli_shell:
        return paths
    return tuple(p for p in paths if "sqli_shell" not in p.lower())


def product_chain_still_pending(kb: Mapping[str, Any]) -> str:
    """
    Return the lab product name while its focused shell chain is incomplete.

    Exploit links only clear after a wrapper attempt (listener-enabled). Mere
    scanner observation without a session must not lift focus into CVE spray.
    Auth/aux links still clear on observation. Shell / explicit backtrack lift focus.
    """
    product = focused_lab_product(kb)
    if not product:
        return ""
    if kb.get("product_shell_backtrack"):
        return ""
    chain = product_shell_chain_paths(product, include_sqli_shell=False)
    if not chain:
        return ""
    wrapper_attempts = {
        str(x).strip().lower()
        for x in (kb.get("product_shell_wrapper_attempts") or [])
        if str(x).strip()
    }
    wrapper_leaves = {a.rsplit("/", 1)[-1] for a in wrapper_attempts}
    for path in chain:
        leaf = path.rsplit("/", 1)[-1]
        low = path.lower()
        if low.startswith(("exploit/", "exploits/")):
            if low not in wrapper_attempts and leaf.lower() not in wrapper_leaves:
                return product
            continue
        if not _module_observed_in_kb(kb, path, leaf):
            return product
    return ""


def product_focus_skip_reason(module_path: str, kb: Mapping[str, Any]) -> str:
    """
    Product-first gate: while DVWA (etc.) chain is pending, do not spray foreign
    WordPress/plugin CVEs or unrelated exploits. Backtrack only after the chain
    modules have been tried.
    """
    product = product_chain_still_pending(kb)
    if not product:
        return ""
    path = str(module_path or "").strip()
    if not path:
        return ""
    low = path.lower()
    chain = product_shell_chain_paths(product, include_sqli_shell=False)
    chain_basenames = {c.rsplit("/", 1)[-1].lower() for c in chain}
    leaf = low.rsplit("/", 1)[-1]
    if low in {c.lower() for c in chain} or leaf in chain_basenames:
        return ""
    if product in low:
        return ""
    if any(tok in low for tok in ("admin_login_bruteforce", "login_page_detector", "simple_login")):
        return ""
    if low.startswith(("exploit/", "exploits/")):
        return (
            f"product-focus: `{product}` shell chain pending "
            f"(auth→RCE first); defer unrelated exploit"
        )
    if any(tok in low for tok in _FOREIGN_CMS_PATH_TOKENS):
        return (
            f"product-focus: `{product}` shell chain pending; "
            f"defer foreign CMS module"
        )
    return ""


def filter_paths_for_product_focus(
    paths: Sequence[str],
    kb: Mapping[str, Any],
) -> List[str]:
    """Keep paths allowed under the current product-focus gate (pass-through when none)."""
    if not product_chain_still_pending(kb):
        return [str(p) for p in paths or [] if str(p).strip()]
    kept: List[str] = []
    for path in paths or []:
        token = str(path or "").strip()
        if not token:
            continue
        if product_focus_skip_reason(token, kb):
            continue
        kept.append(token)
    if kept:
        return kept
    # Ensure the pending chain itself remains reachable even if the input list
    # only contained foreign CVEs.
    product = product_chain_still_pending(kb)
    return list(product_shell_chain_paths(product, include_sqli_shell=False))


def is_shell_operator_goal(goal: Optional[str]) -> bool:
    return normalize_goal(goal) in SHELL_OPERATOR_GOALS


def is_auth_operator_goal(goal: Optional[str]) -> bool:
    return normalize_goal(goal) in AUTH_OPERATOR_GOALS


def is_exploit_operator_goal(goal: Optional[str]) -> bool:
    return normalize_goal(goal) in EXPLOIT_OPERATOR_GOALS


def operator_goal_from_mapping(mapping: Any) -> str:
    """Read normalized operator goal from state dict or knowledge base."""
    if not isinstance(mapping, dict):
        return ""
    raw = (
        mapping.get("operator_goal")
        or mapping.get("operator_campaign_goal")
        or mapping.get("planner_campaign_goal")
        or mapping.get("campaign_goal")
        or ""
    )
    return normalize_goal(str(raw).strip() or None) if str(raw).strip() else ""


def kb_auth_terminal_reached(kb: Any) -> bool:
    """True when KB risk signals indicate credentials or an authenticated session."""
    if not isinstance(kb, Mapping):
        return False
    signals = {str(s).lower() for s in (kb.get("risk_signals") or [])}
    return bool(signals.intersection(AUTH_TERMINAL_SIGNALS))


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


def api_module_candidates(
    kb: Mapping[str, Any],
    *,
    prefer_js: bool = False,
) -> List[str]:
    """Deterministic admissible API/JS module paths (not yet observed)."""
    ladder: List[tuple[str, str]] = list(SHELL_API_MODULE_LADDER)
    if prefer_js:
        js_rows = (
            [row for row in ladder if row[1] == "js_endpoint"]
            + [row for row in ladder if row[1] == "js_sourcemap"]
        )
        rest = [row for row in ladder if row[1] not in ("js_sourcemap", "js_endpoint")]
        ladder = js_rows + rest
    out: List[str] = []
    for path, needle in ladder:
        if not _module_observed_in_kb(kb, needle):
            out.append(path)
    return out


def rank_api_module_candidates(
    kb: Mapping[str, Any],
    state: Any = None,
    *,
    candidates: Optional[Sequence[str]] = None,
) -> List[str]:
    """
    Order API module candidates. Without LLM: heuristic ladder order.
    With LLM connected: prefer modules matching recent HTTP probe evidence.
    """
    hints_blob = " ".join(str(h).lower() for h in kb.get("tech_hints", []) or [])
    prefer_js = any(
        t in hints_blob for t in ("nextjs", "nodejs", "react", "javascript", "angular", "vue")
    )
    ordered = list(candidates or api_module_candidates(kb, prefer_js=prefer_js))
    if not ordered:
        return []

    evidence_blob = " ".join(
        [
            " ".join(str(e).lower() for e in (kb.get("discovered_endpoints") or [])[:24]),
            " ".join(
                f"{row.get('url', '')} {row.get('body_sample', '')} {row.get('status_code', '')}"
                for row in (kb.get("llm_http_requests") or [])[-8:]
                if isinstance(row, dict)
            ),
            " ".join(str(s).lower() for s in (kb.get("risk_signals") or [])),
        ]
    ).lower()

    def _score(path: str) -> tuple:
        low = path.lower()
        score = 0
        if "swagger" in low and any(t in evidence_blob for t in ("swagger", "openapi")):
            score += 40
        if "graphql" in low and "graphql" in evidence_blob:
            score += 40
        if "api_fuzzer" in low and any(t in evidence_blob for t in ("/api", "json", "rest")):
            score += 25
        if "js_endpoint" in low or "js_sourcemap" in low:
            if prefer_js or ".js" in evidence_blob:
                score += 30
        try:
            base = ordered.index(path)
        except ValueError:
            base = 99
        return (-score, base)

    ranked = sorted(ordered, key=_score)
    try:
        from interfaces.command_system.builtin.agent.http_probe_actions import llm_connected

        if llm_connected(state):
            kb_mutable = kb if isinstance(kb, dict) else {}
            if isinstance(kb_mutable, dict):
                kb_mutable["api_modules_ranked"] = list(ranked)
            return ranked
    except Exception:
        pass
    return ordered

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


_SSH_HINT_TOKENS = frozenset({"ssh", "openssh"})
_SSH_SERVICE_PORTS = frozenset({22, 2222, 2223, 2200, 2022})
_SMB_HINT_TOKENS = frozenset({"smb", "cifs", "microsoft-ds", "netbios-ssn"})
_SMB_SERVICE_PORTS = frozenset({139, 445})


SHELL_SMB_MODULE_LADDER: Sequence[tuple[str, str]] = (
    ("auxiliary/scanner/smb/smb_enumshares", "smb_enumshares"),
    ("auxiliary/scanner/smb/session_acquire", "session_acquire"),
    ("auxiliary/scanner/smb/smb_relay_surface_audit", "smb_relay"),
)


def _forced_protocol(kb: Mapping[str, Any], state: Any = None) -> str:
    return str(getattr(state, "protocol", "") or (kb.get("protocol") if isinstance(kb, Mapping) else "") or "").strip().lower()


def _parse_service_port(token: str) -> Optional[int]:
    text = str(token or "").strip().lower()
    if not text:
        return None
    for sep in (":", "/"):
        if sep in text:
            tail = text.rsplit(sep, 1)[-1]
            if tail.isdigit():
                return int(tail)
    if text.isdigit():
        return int(text)
    return None


def _token_is_ssh_service(token: str) -> bool:
    """True when a service token clearly identifies SSH (not a substring false positive)."""
    text = str(token or "").strip().lower()
    if not text:
        return False
    if text in _SSH_HINT_TOKENS or text.startswith("ssh/") or text.startswith("ssh:"):
        return True
    if text.startswith("openssh"):
        return True
    port = _parse_service_port(text)
    if port is None:
        return False
    # Bare ssh-labelled ports (ssh:2223, openssh/22). Avoid matching host:2223 alone —
    # remapped lab ports need an ssh/openssh label unless the port is canonical :22.
    if "ssh" in text.split(":")[0].split("/")[0] or "openssh" in text:
        return port in _SSH_SERVICE_PORTS or port > 0
    return port == 22


def kb_ssh_surface_ready(kb: Mapping[str, Any], state: Any = None) -> bool:
    """
    True when SSH is an intentional engagement surface.

    Forced ``--protocol http|https`` never claims SSH readiness (stale host-profile
    hints like ``openssh`` must not pivot a web campaign onto ssh_login).
    """
    if not isinstance(kb, Mapping):
        kb = {}
    protocol = _forced_protocol(kb, state)
    if protocol in {"http", "https"}:
        return False
    if protocol == "ssh":
        return True
    for item in kb.get("identified_services", []) or []:
        if _token_is_ssh_service(str(item or "")):
            return True
    hint_tokens = {
        str(h).strip().lower()
        for h in (kb.get("tech_hints", []) or [])
        if str(h).strip()
    }
    if hint_tokens.intersection(_SSH_HINT_TOKENS):
        # Exact hint tokens only — never ``"ssh" in blob`` substring matching.
        # Prefer corroborating service/port evidence; allow exact hints only when
        # the operator did not force another protocol family.
        for item in kb.get("identified_services", []) or []:
            if _token_is_ssh_service(str(item or "")):
                return True
        for item in kb.get("discovered_open_ports", []) or []:
            try:
                if int(item) in _SSH_SERVICE_PORTS:
                    return True
            except (TypeError, ValueError):
                continue
        if not protocol:
            return True
    return False


def kb_smb_surface_ready(kb: Mapping[str, Any], state: Any = None) -> bool:
    """True when SMB/CIFS is an intentional engagement surface."""
    if not isinstance(kb, Mapping):
        kb = {}
    protocol = _forced_protocol(kb, state)
    if protocol in {"http", "https", "ssh"}:
        return False
    if protocol in {"smb", "cifs"}:
        return True
    for item in kb.get("identified_services", []) or []:
        low = str(item or "").lower()
        if any(tok in low for tok in _SMB_HINT_TOKENS):
            return True
    hints = {str(h).strip().lower() for h in (kb.get("tech_hints") or []) if str(h).strip()}
    if hints.intersection(_SMB_HINT_TOKENS):
        return True
    for item in kb.get("discovered_open_ports", []) or kb.get("open_ports") or []:
        try:
            if int(item) in _SMB_SERVICE_PORTS:
                return True
        except (TypeError, ValueError):
            continue
    signals = {str(s).lower() for s in (kb.get("risk_signals") or [])}
    return bool(signals.intersection({"smb_surface", "smb_detected", "cifs_detected"}))


_LOCAL_RF_PATH_TOKENS = (
    "/bluetooth/",
    "/ble/",
    "ble_scan",
    "bleedingtooth",
    "/wifi/",
    "/wireless/",
    "/nfc/",
    "/zigbee/",
    "/zwave/",
    "/z-wave/",
    "rfkill",
    "classic_scan",
)


def is_local_rf_module_path(path: str) -> bool:
    """True for host-local RF modules (BLE/WiFi/NFC/…) that cannot target a remote URL."""
    low = str(path or "").strip().lower()
    return bool(low) and any(token in low for token in _LOCAL_RF_PATH_TOKENS)


def resolve_campaign_protocol(
    state: Any = None,
    kb: Optional[Mapping[str, Any]] = None,
) -> str:
    """Resolve effective protocol from state, KB, or target URL scheme.

    HTTPS targets resolve to ``http`` because module trees live under
    ``scanner/http/`` / ``auxiliary/scanner/http/``.
    """
    proto = ""
    if state is not None:
        proto = str(getattr(state, "protocol", "") or "").strip().lower()
    if not proto and isinstance(kb, Mapping):
        proto = str(kb.get("protocol") or "").strip().lower()
    if not proto and state is not None:
        target_info = getattr(state, "target_info", None) or {}
        if isinstance(target_info, Mapping):
            scheme = str(target_info.get("scheme") or "").strip().lower()
            if scheme:
                proto = scheme
        if not proto:
            raw = str(getattr(state, "raw_target", "") or "").strip().lower()
            if raw.startswith("https://"):
                proto = "https"
            elif raw.startswith("http://"):
                proto = "http"
    if proto == "https":
        return "http"
    return proto


def path_matches_forced_protocol(path: str, protocol: str) -> bool:
    """Return False when a module path clearly conflicts with an operator-forced protocol."""
    proto = str(protocol or "").strip().lower()
    low = str(path or "").strip().lower()
    if not low:
        return True
    if proto in {"http", "https"} and is_local_rf_module_path(low):
        return False
    if not proto:
        return True
    if proto in {"http", "https"}:
        foreign = (
            "/android/",
            "/adb/",
            "/ssh/",
            "scanner/ssh/",
            "/smb/",
            "/ftp/",
            "/ldap/",
            "/rdp/",
            "/vnc/",
            "/bluetooth/",
            "/ble/",
            "/wifi/",
            "/wireless/",
            "/nfc/",
            "/zigbee/",
            "/zwave/",
        )
        if any(token in low for token in foreign):
            return False
        if low.rstrip("/").endswith("ssh_login") or "openssh_banner" in low:
            return False
        if low.startswith(("scanner/http/", "auxiliary/scanner/http/", "post/http/")):
            return True
        if low.startswith(("exploits/http/", "exploits/multi/http/")):
            return True
        # A few legacy web modules omit the protocol segment but are still HTTP apps.
        if low.startswith("exploits/ctf/dvwa"):
            return True
        return not low.startswith(("exploits/", "scanner/", "auxiliary/scanner/", "post/"))
    if proto == "ssh":
        if "/http/" in low or "/https/" in low:
            # Allow post-auth HTTP only when not forced to ssh-only recon.
            return False
        return "/ssh/" in low or "ssh_login" in low or low.startswith("post/")
    # Other forced protocols: keep matching family paths.
    return f"/{proto}/" in low or f"scanner/{proto}/" in low or f"auxiliary/scanner/{proto}/" in low


def _kb_confidence(kb: Mapping[str, Any], tech: str) -> float:
    conf = kb.get("tech_confidence", {}) if isinstance(kb, Mapping) else {}
    try:
        return float((conf or {}).get(str(tech).lower(), 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _agent_requires_match(agent: Mapping[str, Any], kb: Mapping[str, Any]) -> bool:
    req = agent.get("requires") if isinstance(agent, Mapping) else {}
    if not isinstance(req, Mapping):
        return True
    hints = {str(x).lower() for x in kb.get("tech_hints", []) or []}
    signals = {str(x).lower() for x in kb.get("risk_signals", []) or []}
    endpoints = [str(e).lower() for e in (kb.get("discovered_endpoints", []) or [])]
    params = {str(p).lower() for p in (kb.get("discovered_params", []) or [])}

    if int(req.get("min_endpoints", 0) or 0) > len(endpoints):
        return False
    if int(req.get("min_params", 0) or 0) > len(params):
        return False
    need_any = [str(x).lower() for x in (req.get("tech_hints_any") or []) if str(x).strip()]
    if need_any and not any(x in hints for x in need_any):
        return False
    need_all = [str(x).lower() for x in (req.get("tech_hints_all") or []) if str(x).strip()]
    if need_all and not all(x in hints for x in need_all):
        return False
    risk_any = [str(x).lower() for x in (req.get("risk_signals_any") or []) if str(x).strip()]
    if risk_any and not any(x in signals for x in risk_any):
        return False
    conf_min = req.get("confidence_min") or {}
    if isinstance(conf_min, Mapping):
        for tech, floor in conf_min.items():
            try:
                if _kb_confidence(kb, str(tech)) < float(floor):
                    return False
            except (TypeError, ValueError):
                continue
    conf_min_any = req.get("confidence_min_any") or {}
    if isinstance(conf_min_any, Mapping) and conf_min_any:
        matched_any = False
        for tech, floor in conf_min_any.items():
            try:
                matched_any = matched_any or _kb_confidence(kb, str(tech)) >= float(floor)
            except (TypeError, ValueError):
                continue
        if not matched_any:
            return False
    endpoint_patterns = [str(x).lower() for x in (req.get("endpoint_pattern_any") or []) if str(x).strip()]
    if endpoint_patterns and not any(pat in ep for ep in endpoints for pat in endpoint_patterns):
        return False
    param_any = [str(x).lower() for x in (req.get("param_any") or []) if str(x).strip()]
    if param_any and not any(p in params for p in param_any):
        return False
    if bool(req.get("api_surface_ready", False)) and not kb_api_surface_ready(kb):
        return False
    if bool(req.get("auth_session", False)) and "authenticated_session" not in signals:
        return False
    return True


def _agent_has_grounding_requirements(agent: Mapping[str, Any]) -> bool:
    req = agent.get("requires") if isinstance(agent, Mapping) else {}
    if not isinstance(req, Mapping):
        return False
    grounding_keys = (
        "tech_hints_any",
        "tech_hints_all",
        "confidence_min",
        "confidence_min_any",
        "endpoint_pattern_any",
        "param_any",
        "risk_signals_any",
        "specializations_any",
        "capabilities_any",
        "capabilities_all",
    )
    for key in grounding_keys:
        value = req.get(key)
        if isinstance(value, Mapping) and value:
            return True
        if isinstance(value, (list, tuple, set)) and any(str(x).strip() for x in value):
            return True
    return bool(req.get("api_surface_ready") or req.get("auth_session"))


def _module_shell_capability_score(module: Mapping[str, Any]) -> float:
    path = str(module.get("path") or "").lower()
    agent = module.get("agent") if isinstance(module.get("agent"), Mapping) else {}
    chain = agent.get("chain") if isinstance(agent, Mapping) and isinstance(agent.get("chain"), Mapping) else {}
    caps = {
        str(row.get("capability") or "").lower()
        for row in (chain.get("produces_capabilities") or [])
        if isinstance(row, Mapping)
    }
    score = 0.0
    if "shell" in caps or "interactive_shell" in caps:
        score += 5.0
    if "rce" in caps:
        score += 4.0
    if "session" in caps:
        score += 2.0
    if path.startswith("exploits/"):
        score += 2.0
    if path.startswith("post/"):
        score += 1.0
    if any(token in path for token in ("rce", "shell", "command_inj", "code_injection", "cve_")):
        score += 1.5
    return score


def _metadata_shell_followups(
    kb: Mapping[str, Any],
    state: Any = None,
    catalog_modules: Optional[Sequence[Mapping[str, Any]]] = None,
) -> List[str]:
    if not catalog_modules:
        return []
    protocol = _forced_protocol(kb, state)
    scored: List[Tuple[float, str]] = []
    for module in catalog_modules:
        if not isinstance(module, Mapping):
            continue
        path = str(module.get("path") or "").strip()
        if not path or _module_observed_in_kb(kb, path, path.rsplit("/", 1)[-1]):
            continue
        if not path.startswith(("exploits/", "post/", "auxiliary/scanner/", "scanner/")):
            continue
        if not path_matches_forced_protocol(path, protocol):
            continue
        agent = module.get("agent") if isinstance(module.get("agent"), Mapping) else {}
        if not isinstance(agent, Mapping) or not agent:
            continue
        cap_score = _module_shell_capability_score(module)
        if cap_score <= 0.0:
            continue
        if path.startswith("exploits/") and not _agent_has_grounding_requirements(agent):
            continue
        if not _agent_requires_match(agent, kb):
            continue
        try:
            value = float(agent.get("value", 1.0) or 1.0)
            cost = float(agent.get("cost", 1.0) or 1.0)
            noise = float(agent.get("noise", 0.5) or 0.5)
        except (TypeError, ValueError):
            value, cost, noise = 1.0, 1.0, 0.5
        scored.append((cap_score + value - (cost * 0.12) - (noise * 0.25), path))
    scored.sort(key=lambda row: (-row[0], row[1]))
    out: List[str] = []
    seen = set()
    for _score, path in scored:
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def _kb_login_surface_ready(kb: Mapping[str, Any]) -> bool:
    if not isinstance(kb, Mapping):
        return False
    if kb_auth_terminal_reached(kb):
        return False
    if any(isinstance(p, str) and p.startswith("/") for p in (kb.get("login_paths") or [])):
        return True
    signals = {str(s).lower() for s in (kb.get("risk_signals") or [])}
    return bool(signals.intersection({
        "login_surface_detected",
        "login_redirect_detected",
        "login_form_detected",
    }))


def product_auth_shell_followups(kb: Mapping[str, Any], state: Any = None) -> List[str]:
    """
    Known lab/product + login chains that must run before metadata CVE noise.

    Used by scan pinning and the adaptive catalog so DVWA/auth is not starved
    when opportunistic scoring prefers unrelated detectors.

    For ``obtain-shell``, omit SQLi pseudo-shell modules — chase OS RCE/webshell.
    """
    if not isinstance(kb, dict):
        return []
    out: List[str] = []
    seen: set = set()
    shell_goal = is_shell_operator_goal(
        operator_goal_from_mapping(kb)
        or (normalize_goal(getattr(state, "operator_goal", None) or getattr(state, "campaign_goal", None)) if state is not None else "")
        or ""
    ) or bool(state is not None and getattr(state, "shell_hunter", False))

    def _add(path: str) -> None:
        if not path or path in seen:
            return
        if shell_goal and "sqli_shell" in path.lower():
            return
        if not _module_observed_in_kb(kb, path, path.rsplit("/", 1)[-1]):
            seen.add(path)
            out.append(path)

    conf = kb.get("tech_confidence", {}) or {}

    def _conf(name: str) -> float:
        try:
            return float(conf.get(name, 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    if _kb_login_surface_ready(kb):
        _add(ADMIN_LOGIN_BRUTEFORCE_MODULE)

    ranked = sorted(
        (( _conf(name), name, paths) for name, paths in _PRODUCT_SHELL_CHAINS.items()),
        key=lambda row: row[0],
        reverse=True,
    )
    for score, _name, paths in ranked:
        if score < 0.45:
            continue
        for path in paths:
            _add(path)
    return out


def suggest_shell_plan_followups(
    kb: Mapping[str, Any],
    state: Any = None,
    catalog_modules: Optional[Sequence[Mapping[str, Any]]] = None,
) -> List[str]:
    """
    Ordered module paths that widen surface toward RCE/shell (used by planner + execution plan).
    Skips modules already present in ``observed_modules``.
    Respects forced ``state.protocol`` / ``kb['protocol']`` (http never pivots to SSH).
    """
    if not isinstance(kb, dict):
        return []
    out: List[str] = []
    seen_paths: set = set()
    protocol = _forced_protocol(kb, state)
    shell_goal = is_shell_operator_goal(
        operator_goal_from_mapping(kb)
        or (
            normalize_goal(getattr(state, "operator_goal", None) or getattr(state, "campaign_goal", None))
            if state is not None
            else ""
        )
        or ""
    ) or bool(state is not None and getattr(state, "shell_hunter", False))

    def _add(path: str) -> None:
        if not path or path in seen_paths:
            return
        if shell_goal and "sqli_shell" in path.lower():
            return
        if not path_matches_forced_protocol(path, protocol):
            return
        seen_paths.add(path)
        out.append(path)

    if kb_ssh_surface_ready(kb, state):
        if not _module_observed_in_kb(kb, "openssh_banner_detect", "ssh_login"):
            _add("scanner/ssh/openssh_banner_detect")
        if not _module_observed_in_kb(kb, "ssh_login"):
            _add("auxiliary/scanner/ssh/ssh_login")
        if out:
            return out

    if kb_smb_surface_ready(kb, state):
        for path, needle in SHELL_SMB_MODULE_LADDER:
            if not _module_observed_in_kb(kb, needle):
                _add(path)
        if out:
            return out

    conf = kb.get("tech_confidence", {}) or {}

    def _conf(name: str) -> float:
        try:
            return float(conf.get(name, 0.0) or 0.0)
        except Exception:
            return 0.0

    def _add_drupal_chain() -> None:
        if _conf("drupal") < 0.45:
            return
        if not _module_observed_in_kb(kb, "drupal_scanner", "drupal_detect"):
            _add("auxiliary/scanner/http/drupal_scanner")
        if not _module_observed_in_kb(kb, "drupal_cve_2014_3704_sqli"):
            _add(DRUPAL_CVE_2014_3704_SQLI_MODULE)
        if not _module_observed_in_kb(kb, "drupal_rce"):
            _add(DRUPAL_DRUPALGEDDON2_MODULE)

    def _add_phpmyadmin_chain() -> None:
        if _conf("phpmyadmin") < 0.4:
            return
        if not _module_observed_in_kb(kb, "phpmyadmin_setup_detect", "phpmyadmin_detect"):
            _add("scanner/http/phpmyadmin_setup_detect")
        if not _module_observed_in_kb(kb, "php_injection", "php_rce"):
            _add("auxiliary/scanner/http/php_injection")

    def _add_dvwa_chain() -> None:
        if _conf("dvwa") < 0.45:
            return
        # Prefer real OS shell (RCE / upload) over SQLi pseudo-shell.
        if not _module_observed_in_kb(kb, "admin_login_bruteforce"):
            _add(ADMIN_LOGIN_BRUTEFORCE_MODULE)
        if not _module_observed_in_kb(kb, "dvwa_rce"):
            _add(DVWA_RCE_MODULE)
        if not _module_observed_in_kb(kb, "dvwa_file_upload"):
            _add(DVWA_FILE_UPLOAD_MODULE)
        # SQLi pseudo-shell is not an OS shell — skip when chasing obtain-shell.
        shell_goal = is_shell_operator_goal(
            operator_goal_from_mapping(kb)
            or (normalize_goal(getattr(state, "operator_goal", None) or getattr(state, "campaign_goal", None)) if state is not None else "")
            or ""
        ) or bool(state is not None and getattr(state, "shell_hunter", False))
        if not shell_goal and not _module_observed_in_kb(kb, "dvwa_sqli_shell"):
            _add(DVWA_SQLI_SHELL_MODULE)

    # Known product/auth chains first — metadata CVE catalogs used to steal these slots.
    for path in product_auth_shell_followups(kb, state):
        _add(path)

    # Highest-confidence product chain first (DVWA must beat co-hosted phpMyAdmin noise).
    for _score, _adder in sorted(
        (
            (_conf("dvwa"), _add_dvwa_chain),
            (_conf("drupal"), _add_drupal_chain),
            (_conf("phpmyadmin"), _add_phpmyadmin_chain),
        ),
        key=lambda item: item[0],
        reverse=True,
    ):
        _adder()

    for path in _metadata_shell_followups(kb, state, catalog_modules):
        _add(path)

    # Confirmed SQLi beats generic API/OSINT noise for shell and exploit chase.
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if signals.intersection({"sqli_confirmed", "sql_signal"}):
        try:
            from interfaces.command_system.builtin.agent.attack_branch import (
                pick_resumed_deep_action,
                sync_branches_from_kb_signals,
            )

            sync_branches_from_kb_signals(kb)
            resume_goal = str(
                kb.get("operator_campaign_goal")
                or kb.get("campaign_goal")
                or getattr(state, "campaign_goal", "")
                or "exploit"
            )
            resumed = pick_resumed_deep_action(kb, operator_goal=resume_goal)
            if resumed and resumed.get("path"):
                _add(str(resumed["path"]))
            elif not _module_observed_in_kb(kb, "sqli_shell"):
                _add("post/http/sqli_shell")
            if not _module_observed_in_kb(kb, "sqli_engine", "sql_injection"):
                _add("auxiliary/scanner/http/sqli_engine")
        except Exception:
            if not _module_observed_in_kb(kb, "sqli_shell"):
                _add("post/http/sqli_shell")
            if not _module_observed_in_kb(kb, "sqli_engine", "sql_injection"):
                _add("auxiliary/scanner/http/sqli_engine")

    if kb_api_surface_ready(kb) or kb_client_js_surface_ready(kb):
        hints_blob = " ".join(str(h).lower() for h in kb.get("tech_hints", []) or [])
        prefer_js = any(
            t in hints_blob for t in ("nextjs", "nodejs", "react", "javascript", "angular", "vue")
        )
        ranked = rank_api_module_candidates(
            kb,
            state,
            candidates=api_module_candidates(kb, prefer_js=prefer_js),
        )
        llm_on = False
        try:
            from interfaces.command_system.builtin.agent.http_probe_actions import llm_connected

            llm_on = llm_connected(state)
        except Exception:
            llm_on = False
        for idx, path in enumerate(ranked):
            _add(path)
            if llm_on:
                # LLM-ranked: admit top two candidates; planner/LLM chooses among them.
                if idx >= 1:
                    break
                continue
            needle = path.rsplit("/", 1)[-1]
            if "js_sourcemap" in needle or "js_endpoint" in needle:
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

    # Deep SQLi shell when a light branch was parked and other shell paths did not land.
    try:
        from interfaces.command_system.builtin.agent.attack_branch import pick_resumed_deep_action

        resume_goal = str(
            kb.get("operator_campaign_goal")
            or kb.get("campaign_goal")
            or getattr(state, "campaign_goal", "")
            or ""
        )
        resumed = pick_resumed_deep_action(kb, operator_goal=resume_goal)
        if resumed and resumed.get("path"):
            _add(str(resumed["path"]))
    except Exception:
        pass

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
        # Tactical / milestone goals may appear mid-campaign; never crash the run.
        token = str(goal or "").strip().lower()
        if any(part in token for part in ("exploit", "shell", "auth", "post")):
            if "post" in token:
                key = "post-auth"
            elif "auth" in token:
                key = "obtain-auth"
            else:
                key = "exploit"
            if key not in GOAL_DEFINITIONS:
                key = "exploit"
        else:
            key = "recon"
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
