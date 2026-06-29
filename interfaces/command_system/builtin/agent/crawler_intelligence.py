#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""KB-guided crawler seeds and bounded bruteforce budgets for the agent."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from interfaces.command_system.builtin.agent.agent_constants import NEXTJS_HINT_TOKENS
from interfaces.command_system.builtin.agent.runtime_policy import assess_module_risk

CRAWLER_MODULE_PATH = "auxiliary/scanner/http/crawler"
BRUTEFORCE_MODULE_PATH = "auxiliary/scanner/http/login/admin_login_bruteforce"

_DEFAULT_SEEDS: tuple[str, ...] = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
)

_API_SEEDS: tuple[str, ...] = (
    "/api",
    "/api/",
    "/graphql",
    "/swagger.json",
    "/openapi.json",
)

_NEXT_SEEDS: tuple[str, ...] = (
    "/_next/static/",
)


def _dedupe_paths(paths: List[str], *, limit: int = 32) -> List[str]:
    out: List[str] = []
    seen: set = set()
    for raw in paths:
        p = str(raw or "").strip()
        if not p.startswith("/"):
            continue
        key = p.split("?", 1)[0].lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p.split("?", 1)[0])
        if len(out) >= limit:
            break
    return out


def build_crawler_seed_paths(
    kb: Mapping[str, Any],
    *,
    limit: int = 28,
) -> List[str]:
    """Priority seed paths: robots/sitemap, KB endpoints, API/Next.js hints."""
    seeds = list(_DEFAULT_SEEDS)
    if not isinstance(kb, dict):
        return _dedupe_paths(seeds, limit=limit)

    hints = {str(h).lower() for h in kb.get("tech_hints", []) or []}
    conf = kb.get("tech_confidence", {}) or {}
    api_ready = float(conf.get("api", 0.0) or 0.0) >= 0.35 or "api" in hints
    next_ready = (
        "nextjs" in hints
        or float(conf.get("nextjs", 0.0) or 0.0) >= 0.4
    )

    for ep in list(kb.get("discovered_endpoints", []) or [])[:24]:
        text = str(ep).strip()
        if text.startswith("/"):
            seeds.append(text.split("?", 1)[0])
        low = text.lower()
        if any(tok in low for tok in ("/api", "graphql", "swagger", "openapi")):
            api_ready = True
        if any(tok.replace("/", "") in low for tok in NEXTJS_HINT_TOKENS if tok.startswith("/")):
            next_ready = True

    for lp in list(kb.get("login_paths", []) or [])[:6]:
        if str(lp).startswith("/"):
            seeds.append(str(lp).split("?", 1)[0])

    if api_ready:
        seeds.extend(_API_SEEDS)
    if next_ready:
        seeds.extend(_NEXT_SEEDS)
        seeds.append("/_next/data/")
        if not api_ready:
            seeds.extend(_API_SEEDS)

    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if signals.intersection({"api_surface_detected", "test_api_surface"}):
        seeds.extend(_API_SEEDS)

    return _dedupe_paths(seeds, limit=limit)


def _intrusive_bruteforce_approved(state: Any) -> bool:
    policy = getattr(state, "runtime_policy", None)
    if policy is None:
        return False
    risk = assess_module_risk({"path": BRUTEFORCE_MODULE_PATH}, BRUTEFORCE_MODULE_PATH)
    try:
        return bool(policy.risk_approved(risk))
    except Exception:
        return False


def bruteforce_attempt_cap(state: Any, *, persona_pairs: int = 0) -> int:
    """Low cap without explicit intrusive approval; higher when approved."""
    if _intrusive_bruteforce_approved(state):
        if persona_pairs > 0:
            return min(36, max(12, persona_pairs))
        return 24
    if getattr(state, "shell_hunter", False):
        return 8
    return 4


def crawler_max_links(state: Any) -> int:
    profile = str(getattr(state, "safety_profile", "normal") or "normal").lower()
    if profile in ("safe", "discreet"):
        return 16
    if profile == "aggressive":
        return 48
    return 28


def build_crawler_option_overrides(
    kb: Mapping[str, Any],
    state: Any,
) -> Dict[str, Dict[str, Any]]:
    seeds = build_crawler_seed_paths(kb if isinstance(kb, dict) else {})
    return {
        CRAWLER_MODULE_PATH: {
            "max_crawl": crawler_max_links(state),
            "max_threads": 2 if str(getattr(state, "safety_profile", "")).lower() == "discreet" else 4,
            "seed_paths": ",".join(seeds),
            "intelligent": True,
            "follow_forms": True,
            "follow_scripts": True,
        },
    }


def merge_crawler_overrides(
    overrides: Dict[str, Dict[str, Any]],
    kb: Mapping[str, Any],
    state: Any,
) -> Dict[str, Dict[str, Any]]:
    merged = dict(overrides or {})
    for path, opts in build_crawler_option_overrides(kb, state).items():
        base = dict(merged.get(path) or {})
        base.update(opts)
        merged[path] = base
    return merged
