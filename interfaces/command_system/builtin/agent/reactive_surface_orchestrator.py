#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reactive sub-agent dispatch when the HTTP/application surface changes.

When new tech hints, endpoints, or interesting URLs appear, refresh domain
delegation (scanner, discover, web_recon, class specialists) and surface an
operator brief: what was found and what happens next.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

from interfaces.command_system.builtin.agent.domain_agent_roles import (
    DOMAIN_CMS,
    DOMAIN_WEB,
    infer_active_domains,
    specialist_keys_for_domains,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

TECH_TO_SPECIALIST: Dict[str, str] = {
    "wordpress": "cms_wordpress",
    "wp_": "cms_wordpress",
    "joomla": "cms_joomla",
    "drupal": "cms_drupal",
    "sharepoint": "cms_sharepoint",
    "spring": "cms_spring",
    "springboot": "cms_spring",
    "laravel": "cms_php",
    "symfony": "cms_php",
    "php": "cms_php",
    "graphql": "graphql_agent",
    "react": "browser_agent",
    "angular": "browser_agent",
    "vue": "browser_agent",
    "mysql": "database_service",
    "mariadb": "database_service",
    "postgres": "database_service",
    "mssql": "database_service",
    "ldap": "ldap_agent",
    "kerberos": "kerberos_agent",
}

_ATTACK_CLASS_FOR_SIGNAL: Dict[str, str] = {
    "login_surface_detected": "auth",
    "sql_signal": "sqli",
    "sqli": "sqli",
    "xss": "xss",
    "ssrf": "ssrf",
    "authz": "authz",
    "bola": "authz",
}


def reactive_surface_enabled(state: Any = None) -> bool:
    env = os.environ.get("KITTYSPLOIT_AGENT_REACTIVE_SURFACE", "").strip().lower()
    if env in {"0", "false", "no", "off"}:
        return False
    if env in {"1", "true", "yes", "on"}:
        return True
    if state is not None:
        kb = getattr(state, "knowledge_base", None)
        if isinstance(kb, dict) and (
            kb.get("attack_specialists_mission")
            or kb.get("owasp_web_mission")
            or kb.get("reactive_surface")
        ):
            return True
        profile = str(getattr(state, "safety_profile", "") or "").strip().lower()
        if profile == "safe":
            return False
    return True


def _http_surface(kb: Mapping[str, Any]) -> bool:
    protocol = str(kb.get("protocol") or "").lower()
    if protocol in {"http", "https"}:
        return True
    services = " ".join(str(s).lower() for s in (kb.get("identified_services") or kb.get("services") or []))
    return any(tok in services for tok in ("http", "https", "web"))


def _interesting_urls(kb: Mapping[str, Any]) -> List[str]:
    rows: List[str] = []
    intel = kb.get("request_intel") if isinstance(kb.get("request_intel"), Mapping) else {}
    for row in intel.get("interesting_requests") or []:
        if not isinstance(row, Mapping):
            continue
        if int(row.get("interesting_score") or 0) < 8:
            continue
        url = str(row.get("url") or row.get("path") or "").strip()
        if url:
            rows.append(url)
    return rows[:8]


def _specialists_for_tech(hints: Sequence[str]) -> List[str]:
    keys: List[str] = []
    seen: Set[str] = set()
    blob = " ".join(str(h).lower() for h in hints)
    for needle, specialist in TECH_TO_SPECIALIST.items():
        if needle in blob and specialist not in seen:
            seen.add(specialist)
            keys.append(specialist)
    return keys


def _baseline_corps_specialists() -> List[str]:
    return ["web_recon", "scanner", "discovery"]


def build_reactive_plan(
    kb: Mapping[str, Any],
    *,
    reasons: Sequence[str],
    new_tech: Sequence[str] = (),
    new_endpoints: Sequence[str] = (),
    new_urls: Sequence[str] = (),
) -> Dict[str, Any]:
    """Map surface delta → domain corps + specialist keys + operator brief."""
    reasons_l = {str(r).lower() for r in reasons}
    domains = infer_active_domains(kb, phase="reason")
    if _http_surface(kb) and DOMAIN_WEB not in domains:
        domains = [DOMAIN_WEB] + domains

    specialists: List[str] = []
    seen: Set[str] = set()

    def _add(key: str) -> None:
        if key and key not in seen:
            seen.add(key)
            specialists.append(key)

    for key in _baseline_corps_specialists():
        _add(key)

    for key in _specialists_for_tech(list(new_tech) + list(kb.get("tech_hints") or [])[:8]):
        _add(key)

    signals = {str(s).lower() for s in (kb.get("risk_signals") or [])}
    for signal, attack in _ATTACK_CLASS_FOR_SIGNAL.items():
        if signal in signals:
            _add(attack if attack in {"sqli", "xss", "ssrf", "auth", "authz"} else attack)

    if "new_endpoint" in reasons_l or new_endpoints:
        _add("discovery")
    if "interesting_url" in reasons_l or new_urls:
        _add("discovery")
        _add("web_recon")

    if DOMAIN_CMS in domains or _specialists_for_tech(kb.get("tech_hints") or []):
        domains = list(dict.fromkeys([DOMAIN_CMS] + domains))

    for key in specialist_keys_for_domains(domains):
        _add(key)

    lines: List[str] = []
    if new_tech:
        lines.append(f"Nouvelle stack / techno: {', '.join(new_tech[:5])}.")
    if new_endpoints:
        lines.append(f"Nouvelles routes: {', '.join(new_endpoints[:4])}.")
    if new_urls:
        lines.append(f"URL intéressante: {new_urls[0]}.")
    if not lines:
        lines.append("Surface HTTP enrichie — replanification des sous-agents.")

    next_steps: List[str] = []
    if "discovery" in specialists:
        next_steps.append("Discover: tester hypothèses d'accès (routes / rôles)")
    if "scanner" in specialists:
        next_steps.append("Scanner: modules de détection adaptés à la stack")
    if any(k.startswith("cms_") for k in specialists):
        next_steps.append("CMS corps: modules produit/CVE sur la techno identifiée")
    if "sqli" in specialists or "database_service" in specialists:
        next_steps.append("SQLi: sqli_engine si params présents")
    if "browser_agent" in specialists or "xss" in specialists:
        next_steps.append("XSS/DOM: scanners + browser si SPA")
    if not next_steps:
        next_steps.append("Web recon: clarifier l'API et les paramètres")

    brief = " ".join(lines)
    return sanitize_nested({
        "reasons": list(reasons)[:8],
        "domains": domains[:6],
        "specialist_keys": specialists[:18],
        "brief": brief[:600],
        "next_steps": next_steps[:5],
        "new_tech": list(new_tech)[:8],
        "new_endpoints": list(new_endpoints)[:8],
        "new_urls": list(new_urls)[:4],
    })


def apply_reactive_delegation(state: Any, plan: Mapping[str, Any]) -> None:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return
    record = sanitize_nested({
        "source": "reactive_surface",
        "domains": list(plan.get("domains") or []),
        "specialist_keys": list(plan.get("specialist_keys") or []),
        "rationale": str(plan.get("brief") or "")[:500],
        "confidence": 0.7,
        "next_steps": list(plan.get("next_steps") or []),
    })
    kb["domain_delegation"] = record
    kb["surface_reaction"] = sanitize_nested(dict(plan))
    kb["surface_reaction"]["pending_replan"] = True
    state.domain_delegation = dict(record)  # type: ignore[attr-defined]
    state.replan_pending = True
    execution_plan = getattr(state, "execution_plan", None)
    if isinstance(execution_plan, dict):
        execution_plan["stale"] = True
        execution_plan["replan_reasons"] = list(plan.get("reasons") or [])
        state.execution_plan = execution_plan


def _print_reactive_brief(state: Any, plan: Mapping[str, Any]) -> None:
    if not getattr(state, "verbose", False):
        return
    try:
        from core.output import print_info

        print_info(str(plan.get("brief") or ""))
        specs = plan.get("specialist_keys") or []
        if specs:
            print_info(f"Sous-agents activés: {', '.join(specs[:12])}")
        for step in plan.get("next_steps") or []:
            print_info(f"→ {step}")
    except Exception:
        pass


def seed_initial_sub_agents(state: Any) -> bool:
    """First HTTP mission cycle: scanner + discover + web_recon."""
    if not reactive_surface_enabled(state):
        return False
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict) or not _http_surface(kb):
        return False
    if kb.get("reactive_corps_seeded"):
        return False
    plan = build_reactive_plan(
        kb,
        reasons=["initial_http_mission"],
        new_tech=[],
        new_endpoints=list(kb.get("discovered_endpoints") or [])[:3],
    )
    plan["brief"] = (
        "Mission HTTP — envoi des sous-agents recon (web_recon), scanner et discover "
        "avant les spécialistes d'attaque."
    )
    apply_reactive_delegation(state, plan)
    kb["reactive_corps_seeded"] = True
    kb["reactive_surface"] = True
    _print_reactive_brief(state, plan)
    return True


def on_surface_replan(
    state: Any,
    *,
    reasons: Sequence[str],
    previous_snapshot: Optional[Mapping[str, Any]] = None,
    current_snapshot: Optional[Mapping[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Called when plan_recalc detects tech/endpoint/URL deltas."""
    if not reactive_surface_enabled(state):
        return None
    surface_reasons = {
        "new_tech",
        "new_endpoint",
        "interesting_url",
        "new_surface",
    }
    if not surface_reasons.intersection({str(r).lower() for r in reasons}):
        return None

    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return None

    prev = previous_snapshot if isinstance(previous_snapshot, Mapping) else {}
    cur = current_snapshot if isinstance(current_snapshot, Mapping) else {}
    prev_tech = set(prev.get("tech") or [])
    cur_tech = set(cur.get("tech") or kb.get("tech_hints") or [])
    new_tech = sorted(cur_tech - prev_tech)
    prev_ep = set(prev.get("endpoints") or [])
    cur_ep = set(cur.get("endpoints") or kb.get("discovered_endpoints") or [])
    new_endpoints = sorted(cur_ep - prev_ep)[:8]
    prev_urls = set(prev.get("interesting_urls") or [])
    cur_urls = set(cur.get("interesting_urls") or _interesting_urls(kb))
    new_urls = sorted(cur_urls - prev_urls)[:4]

    plan = build_reactive_plan(
        kb,
        reasons=reasons,
        new_tech=new_tech,
        new_endpoints=new_endpoints,
        new_urls=new_urls,
    )

    try:
        from interfaces.command_system.builtin.agent.framework_expert import consult_framework_expert

        attack = ""
        if new_tech:
            attack = str(new_tech[0]).lower()
        for sig, cls in _ATTACK_CLASS_FOR_SIGNAL.items():
            if sig in {str(s).lower() for s in (kb.get("risk_signals") or [])}:
                attack = cls
                break
        expert = consult_framework_expert(
            state=state,
            attack_class=attack,
            terms=list(new_tech) + [u.split("/")[-1] for u in new_urls[:2]],
            question=plan.get("brief") or "",
            kb=kb,
            limit=6,
        )
        plan["framework_expert"] = {
            "answer": expert.get("answer"),
            "top_modules": [m.get("path") for m in (expert.get("modules") or [])[:4]],
        }
    except Exception:
        pass

    apply_reactive_delegation(state, plan)
    _print_reactive_brief(state, plan)

    try:
        from interfaces.command_system.builtin.agent.specialist_chaos import bump_plan_epoch

        bump_plan_epoch(state)
    except Exception:
        pass

    return dict(plan)


def consume_surface_replan(state: Any) -> bool:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return False
    reaction = kb.get("surface_reaction")
    if not isinstance(reaction, dict) or not reaction.get("pending_replan"):
        return False
    reaction["pending_replan"] = False
    kb["surface_reaction"] = reaction
    return True
