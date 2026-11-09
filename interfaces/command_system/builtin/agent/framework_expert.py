#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Read-only KittySploit framework expert — module search, agent.chain, and attack playbooks.

Used by the mission orchestrator (``consult_framework_expert``), the agent runtime tool
loop, and MCP ``ks_consult_framework_expert``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from interfaces.command_system.builtin.agent.domain_agent_roles import (
    DOMAIN_AGENT_KEYS,
    infer_active_domains,
    specialist_keys_for_domains,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.specialist_attack_intel import (
    FRAMEWORK_PLAYBOOKS,
    mandate_category,
    score_module_path,
)

_ATTACK_CLASS_DOMAINS: Dict[str, Sequence[str]] = {
    "sqli": ("web", "sql"),
    "xss": ("web",),
    "lfi": ("web",),
    "ssrf": ("web",),
    "ssti": ("web",),
    "auth": ("web", "identity"),
    "authz": ("web", "identity"),
    "discovery": ("web",),
    "rce": ("web",),
    "xxe": ("web",),
    "active_directory": ("ad", "identity", "network"),
    "ldap": ("ad", "identity"),
    "kerberos": ("ad", "identity"),
}

_TOKEN_RE = re.compile(r"[a-z0-9_./-]{2,}", re.I)


def _terms_from_question(question: str, attack_class: str, terms: Sequence[Any]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for raw in list(terms or []) + [attack_class, question]:
        for token in _TOKEN_RE.findall(str(raw or "").lower()):
            if token in seen or token in {"the", "and", "for", "with", "module", "modules"}:
                continue
            seen.add(token)
            out.append(token)
    return out[:16]


def _module_catalog(state: Any, framework: Any = None) -> Any:
    fw = framework
    if fw is None and state is not None:
        fw = getattr(state, "framework", None)
        services = getattr(state, "services", None)
        if services is not None:
            catalog = getattr(services, "module_catalog", None)
            if catalog is not None:
                return catalog
    if fw is not None:
        from interfaces.command_system.builtin.agent.module_catalog import ModuleCatalogService

        return ModuleCatalogService(fw)
    return None


def _search_modules(framework: Any, query: str, *, limit: int) -> List[Dict[str, Any]]:
    if framework is None or not query.strip():
        return []
    from core.module_search import ModuleSearchFilters

    try:
        hits = framework.search_modules_db(ModuleSearchFilters(query=query[:200], limit=limit)) or []
    except Exception:
        hits = []
    rows: List[Dict[str, Any]] = []
    for row in hits:
        if not isinstance(row, dict):
            continue
        path = str(row.get("path") or row.get("module_path") or "").strip()
        if not path:
            continue
        rows.append({
            "path": path,
            "name": row.get("name") or path,
            "type": row.get("type"),
            "description": str(row.get("description") or "")[:240],
            "tags": list(row.get("tags") or [])[:12],
        })
    return rows


def _chain_row(catalog_svc: Any, path: str) -> Dict[str, Any]:
    if catalog_svc is None:
        return {}
    try:
        meta = catalog_svc.get_agent_metadata(path)
    except Exception:
        return {}
    if not isinstance(meta, Mapping):
        return {}
    chain = meta.get("chain") if isinstance(meta.get("chain"), Mapping) else {}
    produces = chain.get("produces_capabilities") or []
    caps: List[str] = []
    for item in produces if isinstance(produces, list) else []:
        if isinstance(item, str):
            caps.append(item)
        elif isinstance(item, Mapping) and item.get("capability"):
            caps.append(str(item["capability"]))
    return sanitize_nested({
        "risk": meta.get("risk"),
        "expected_requests": meta.get("expected_requests"),
        "produces_capabilities": caps[:8],
        "consumes_capabilities": list(chain.get("consumes_capabilities") or [])[:8],
        "suggested_followups": list(chain.get("suggested_followups") or [])[:6],
    })


def consult_framework_expert(
    *,
    state: Any = None,
    framework: Any = None,
    question: str = "",
    attack_class: str = "",
    terms: Optional[Sequence[Any]] = None,
    kb: Optional[Mapping[str, Any]] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """
    Return ranked modules, domain/specialist hints, and chain context (read-only).
    """
    kb = kb if isinstance(kb, Mapping) else {}
    if state is not None and not kb:
        live = getattr(state, "knowledge_base", None)
        if isinstance(live, dict):
            kb = live
    fw = framework or getattr(state, "framework", None)
    attack = mandate_category(str(attack_class or "").strip().lower())
    tokens = _terms_from_question(question, attack, terms or ())
    query = " ".join(tokens)
    if attack and attack not in query:
        query = f"{attack} {query}".strip()

    catalog_svc = _module_catalog(state, fw)
    ranked_modules: List[Dict[str, Any]] = []
    for row in _search_modules(fw, query, limit=max(limit, 12)):
        path = row["path"]
        score = score_module_path(path, attack or "web_recon", kb)
        if attack:
            score += 8.0
        entry = dict(row)
        entry["framework_score"] = round(score, 1)
        chain = _chain_row(catalog_svc, path)
        if chain:
            entry["agent"] = chain
        ranked_modules.append(entry)
    ranked_modules.sort(key=lambda r: float(r.get("framework_score") or 0.0), reverse=True)
    ranked_modules = ranked_modules[: max(1, min(int(limit or 10), 20))]

    signal_domains = infer_active_domains(kb, phase=str(kb.get("phase") or ""))
    class_domains = list(_ATTACK_CLASS_DOMAINS.get(attack, ()))
    recommended_domains: List[str] = []
    for domain in class_domains + signal_domains:
        if domain in DOMAIN_AGENT_KEYS and domain not in recommended_domains:
            recommended_domains.append(domain)
    if not recommended_domains:
        recommended_domains = signal_domains[:3] or ["web"]

    specialists = specialist_keys_for_domains(recommended_domains)
    if attack:
        related = [attack]
        for key in specialists:
            if key == attack or mandate_category(key) == attack:
                if key not in related:
                    related.append(key)
        for key in specialists:
            if key not in related and len(related) < 10:
                related.append(key)
        specialists = related

    chain_summary: Dict[str, Any] = {}
    try:
        from interfaces.command_system.builtin.agent.attack_chain_memory import export_chain_summary

        chain_summary = export_chain_summary(kb)
    except Exception:
        chain_summary = {}

    playbook = FRAMEWORK_PLAYBOOKS.get(attack) or ""
    answer_parts = [
        f"Attack class `{attack or 'general'}` — domains {recommended_domains}.",
    ]
    if ranked_modules:
        top = ranked_modules[0]
        answer_parts.append(f"Top module: {top.get('path')} (score {top.get('framework_score')}).")
    if chain_summary.get("capabilities"):
        answer_parts.append(
            "Confirmed capabilities: " + ", ".join(chain_summary.get("capabilities")[:6]) + "."
        )
    if playbook:
        answer_parts.append(playbook[:280])

    result = sanitize_nested({
        "ok": True,
        "question": str(question or "")[:500],
        "attack_class": attack or None,
        "query": query,
        "answer": " ".join(answer_parts)[:1200],
        "framework_playbook": playbook[:700] or None,
        "recommended_domains": recommended_domains,
        "recommended_specialists": specialists[:16],
        "modules": ranked_modules,
        "attack_chain_memory": chain_summary,
    })

    if state is not None:
        target = getattr(state, "knowledge_base", None)
        if isinstance(target, dict):
            target["framework_expert_last"] = dict(result)
            ctx = getattr(state, "planner_llm_context", None)
            if isinstance(ctx, dict):
                ctx["framework_expert"] = {
                    "answer": result.get("answer"),
                    "top_modules": [m.get("path") for m in ranked_modules[:5]],
                    "specialists": specialists[:8],
                }
    return result
