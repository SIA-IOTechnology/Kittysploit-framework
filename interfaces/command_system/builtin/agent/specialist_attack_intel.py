#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Framework-aware context for attack-class specialist agents.

Combines OWASP mandates (vuln_specialists), module path heuristics, and
``__info__['agent'].chain`` metadata so the specialist LLM ranks real KittySploit
modules instead of generic technique prose alone.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.specialist_registry import SpecialistProfile
from interfaces.command_system.builtin.agent.vuln_specialists import (
    SPECIALIST_HINTS,
    _PATH_CATEGORY_MAP,
)

# Specialist registry key → mandate block in SPECIALIST_HINTS (when keys differ).
_MANDATE_KEY_ALIASES: Dict[str, str] = {
    "database_service": "sqli",
    "graphql_agent": "graphql_agent",
    "jwt_agent": "jwt_agent",
    "cloud_aws": "cloud_aws",
    "active_directory": "active_directory",
    "browser_agent": "xss",
}

# Path substring tokens used to rank admissible catalog rows per specialist.
SPECIALIST_PATH_TOKENS: Dict[str, Tuple[str, ...]] = {
    "sqli": (
        "sqli_engine",
        "sql_injection",
        "sqli",
        "sql_inject",
        "blind_sqli",
        "union_sqli",
    ),
    "xss": ("xss", "dom_xss", "cross_site_script", "stored_xss", "reflected_xss"),
    "lfi": ("lfi", "path_traversal", "file_inclusion", "log_poison", "directory_traversal"),
    "ssti": ("ssti", "template_injection", "jinja", "freemarker", "twig"),
    "ssrf": ("ssrf", "server_side_request", "cloud_metadata"),
    "auth": ("login", "bruteforce", "credential", "password_spray", "jwt", "oauth", "oidc"),
    "authz": ("bola", "idor", "broken_access", "authz", "mass_assignment", "privilege"),
    "xxe": ("xxe", "xml_external", "xml_injection"),
    "rce": ("command_injection", "rce", "ognl", "spring4shell", "shell_shock"),
    "upload": ("file_upload", "unrestricted_upload", "upload"),
    "deser": ("deserialization", "pickle", "java_deser", "unserialize", "viewstate"),
    "csrf": ("csrf", "cross_site_request"),
    "cors": ("cors", "cross_origin"),
    "graphql_agent": ("graphql",),
    "jwt_agent": ("jwt", "jwk", "json_web_token"),
    "discovery": ("crawler", "spider", "surface", "enum", "discovery"),
    "web_recon": (
        "crawler",
        "spider",
        "api",
        "swagger",
        "openapi",
        "graphql",
        "login_page",
        "tech_detect",
    ),
}

# Canonical module paths the framework expects for each attack class (documentation + scoring boost).
SPECIALIST_ANCHOR_MODULES: Dict[str, Tuple[str, ...]] = {
    "sqli": (
        "auxiliary/scanner/http/sqli_engine",
        "post/http/sqli_shell",
    ),
    "xss": (
        "auxiliary/scanner/http/xss_scanner",
    ),
    "discovery": (),
    "web_recon": (
        "auxiliary/scanner/http/crawler",
    ),
}

FRAMEWORK_PLAYBOOKS: Dict[str, str] = {
    "sqli": (
        "KITTYSPLOIT SQLi PLAYBOOK: (1) Require crawl/recon params or seed_paths in KB. "
        "(2) Prefer auxiliary/scanner/http/sqli_engine — low-noise oracles via "
        "lib.protocols.http.sqli_engine (error/boolean/time/union, budget-aware). "
        "(3) On capability inj_param / db_access and intrusive RoE, chain "
        "post/http/sqli_shell. (4) Do not spray exploit-only CVE modules before engine confirmation."
    ),
    "xss": (
        "KITTYSPLOIT XSS PLAYBOOK: (1) Classify reflected vs stored vs DOM from KB params and responses. "
        "(2) Rank auxiliary/scanner/http modules whose paths/tags mention xss or dom_xss. "
        "(3) When DOM sinks or client-side routing appear in tech_hints, defer validation to "
        "browser_agent / browser_auxiliary after a scanner flags reflection. "
        "(4) Confirm execution context, not bare reflection."
    ),
    "lfi": (
        "KITTYSPLOIT LFI PLAYBOOK: Prefer dedicated lfi/path_traversal scanners; chain log-poison "
        "modules only after a read primitive is evidenced in findings."
    ),
    "discovery": (
        "KITTYSPLOIT DISCOVERY PLAYBOOK: Read kb.discovery hypotheses and surface routes. "
        "Do not select exploit modules. Prefer bounded http_request probes or passive scanners "
        "that widen params/endpoints. Prove access-control breaks with differential oracle "
        "(role A vs role B on same object_id), never a lone HTTP 200."
    ),
    "authz": (
        "KITTYSPLOIT AUTHZ PLAYBOOK: Prefer api_bola_idor / broken_access scanners; require "
        "cross-identity differential proof before intrusive follow-ups."
    ),
    "web_recon": (
        "KITTYSPLOIT WEB RECON PLAYBOOK: Crawl/API discovery before class-specific exploit modules. "
        "Prefer crawler, swagger/openapi detectors, login_page_detector, tech fingerprint modules."
    ),
}


def mandate_category(specialist_key: str) -> str:
    key = str(specialist_key or "").strip().lower()
    if key in SPECIALIST_HINTS:
        return key
    if key in _MANDATE_KEY_ALIASES:
        return _MANDATE_KEY_ALIASES[key]
    for needle, category in _PATH_CATEGORY_MAP.items():
        if needle == key or key.endswith(f"_{needle}") or key.startswith(f"{needle}_"):
            return category
    return key


def _path_tokens_for_key(specialist_key: str) -> Tuple[str, ...]:
    cat = mandate_category(specialist_key)
    tokens = list(SPECIALIST_PATH_TOKENS.get(cat, ()))
    tokens.extend(SPECIALIST_PATH_TOKENS.get(specialist_key, ()))
    if cat != specialist_key:
        tokens.append(cat)
    if specialist_key not in tokens:
        tokens.append(specialist_key)
    # Dedupe preserving order
    seen: set[str] = set()
    out: List[str] = []
    for token in tokens:
        t = str(token or "").lower()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return tuple(out)


def score_module_path(module_path: str, specialist_key: str, kb: Optional[Mapping[str, Any]] = None) -> float:
    low = str(module_path or "").lower()
    if not low:
        return 0.0
    score = 0.0
    for token in _path_tokens_for_key(specialist_key):
        if len(token) >= 3 and token in low:
            score += 12.0
    cat = mandate_category(specialist_key)
    for anchor in SPECIALIST_ANCHOR_MODULES.get(cat, ()):
        if low == anchor.lower() or low.endswith(anchor.lower().split("/")[-1]):
            score += 28.0
    kb = kb if isinstance(kb, Mapping) else {}
    signals = {str(x).lower() for x in (kb.get("risk_signals") or [])}
    if cat in signals or specialist_key in signals:
        score += 4.0
    if cat == "sqli" and signals.intersection({"sql_signal", "sqli_confirmed"}):
        score += 6.0
    return score


def _chain_summary(agent_meta: Any) -> Dict[str, Any]:
    if not isinstance(agent_meta, Mapping):
        return {}
    chain = agent_meta.get("chain")
    if not isinstance(chain, Mapping):
        return {}
    produces = chain.get("produces_capabilities") or []
    consumes = chain.get("consumes_capabilities") or []
    followups = chain.get("suggested_followups") or []
    cap_out: List[str] = []
    for row in produces if isinstance(produces, list) else []:
        if isinstance(row, str):
            cap_out.append(row)
        elif isinstance(row, Mapping):
            cap = row.get("capability")
            if cap:
                cap_out.append(str(cap))
    return {
        "produces_capabilities": cap_out[:8],
        "consumes_capabilities": [str(x) for x in consumes if str(x).strip()][:8],
        "suggested_followups": [str(x) for x in followups if str(x).strip()][:6],
    }


def _lookup_agent_meta(state: Any, module_path: str) -> Optional[Mapping[str, Any]]:
    services = getattr(state, "services", None)
    catalog_svc = getattr(services, "module_catalog", None) if services is not None else None
    if catalog_svc is None:
        return None
    try:
        meta = catalog_svc.get_agent_metadata(module_path)
    except Exception:
        return None
    if not isinstance(meta, Mapping):
        return None
    return meta


def rank_framework_modules(
    specialist_key: str,
    catalog_paths: Sequence[str],
    kb: Optional[Mapping[str, Any]] = None,
    *,
    limit: int = 8,
) -> List[Dict[str, Any]]:
    scored: List[Tuple[float, str]] = []
    seen: set[str] = set()
    for path in catalog_paths:
        p = str(path or "").strip()
        if not p or p in seen:
            continue
        seen.add(p)
        s = score_module_path(p, specialist_key, kb)
        if s > 0:
            scored.append((s, p))
    cat = mandate_category(specialist_key)
    for anchor in SPECIALIST_ANCHOR_MODULES.get(cat, ()):
        if anchor in seen:
            continue
        s = score_module_path(anchor, specialist_key, kb)
        if s >= 20:
            scored.append((s, anchor))
    scored.sort(key=lambda row: row[0], reverse=True)
    rows: List[Dict[str, Any]] = []
    for score, path in scored[: max(1, int(limit or 8))]:
        rows.append({"path": path, "framework_match_score": round(score, 1)})
    return rows


def build_specialist_attack_context(
    profile: SpecialistProfile,
    kb: Mapping[str, Any],
    catalog: Sequence[Any],
    *,
    state: Any = None,
    max_modules: int = 8,
) -> Dict[str, Any]:
    """Compact payload fragment for specialist LLM calls."""
    kb = kb if isinstance(kb, Mapping) else {}
    paths: List[str] = []
    for row in catalog or []:
        path = getattr(row, "module_path", None) or (row.get("module_path") if isinstance(row, Mapping) else "")
        if path:
            paths.append(str(path))

    cat = mandate_category(profile.key)
    recommended = rank_framework_modules(profile.key, paths, kb, limit=max_modules)

    for row in recommended:
        path = str(row.get("path") or "")
        meta = _lookup_agent_meta(state, path) if state is not None else None
        if meta:
            row["agent_risk"] = meta.get("risk")
            row["expected_requests"] = meta.get("expected_requests")
            chain = _chain_summary(meta)
            if chain:
                row["chain"] = chain

    mandate = SPECIALIST_HINTS.get(cat) or SPECIALIST_HINTS.get(profile.key) or ""
    playbook = FRAMEWORK_PLAYBOOKS.get(cat) or FRAMEWORK_PLAYBOOKS.get(profile.key) or ""

    discovery_block: Dict[str, Any] = {}
    if profile.key == "discovery" or cat == "discovery":
        raw = kb.get("discovery")
        if isinstance(raw, Mapping):
            open_h = [
                str(h.get("statement") or "")[:200]
                for h in (raw.get("hypotheses") or [])
                if isinstance(h, Mapping) and str(h.get("status") or "open") == "open"
            ][:4]
            discovery_block = {
                "open_hypotheses": open_h,
                "novelty": raw.get("novelty") if isinstance(raw.get("novelty"), Mapping) else {},
            }

    return sanitize_nested({
        "mandate_category": cat,
        "owasp_mandate": mandate[:900] if mandate else profile.description[:400],
        "framework_playbook": playbook[:700] if playbook else None,
        "recommended_modules": recommended,
        "kb_attack_signals": {
            "risk_signals": list(kb.get("risk_signals") or [])[:16],
            "tech_hints": list(kb.get("tech_hints") or [])[:12],
            "endpoint_count": len(kb.get("discovered_endpoints") or []),
            "param_hints": list(kb.get("param_hints") or kb.get("seed_params") or [])[:12],
        },
        "discovery": discovery_block or None,
    })


def specialist_llm_instruction(
    profile: SpecialistProfile,
    attack_context: Optional[Mapping[str, Any]] = None,
    *,
    base_instruction: str,
) -> str:
    """Extend the rank instruction with mandate + framework playbook."""
    ctx = attack_context if isinstance(attack_context, Mapping) else {}
    mandate = str(ctx.get("owasp_mandate") or profile.description or "")[:900]
    playbook = str(ctx.get("framework_playbook") or "")[:700]
    parts = [base_instruction, f" SPECIALIST MANDATE: {mandate}"]
    if playbook:
        parts.append(f" FRAMEWORK: {playbook}")
    modules = ctx.get("recommended_modules")
    if isinstance(modules, list) and modules:
        paths = [str(m.get("path") or "") for m in modules[:5] if isinstance(m, Mapping)]
        paths = [p for p in paths if p]
        if paths:
            parts.append(f" PRIORITY MODULE PATHS (if admissible): {', '.join(paths)}.")
    text = "".join(parts)
    return text[:2800]
