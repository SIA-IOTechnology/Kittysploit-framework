#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Stack-aware module gating (declarative ``agent`` metadata + path inference)."""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional

from interfaces.command_system.builtin.agent.module_state_match import (
    module_matches_state,
    module_mismatch_reason,
)

CMS_PATH_TOKENS: Dict[str, tuple[str, ...]] = {
    "wordpress": ("wordpress", "wp_", "wp-", "wpvivid", "wp_plugin"),
    "drupal": ("drupal",),
    "joomla": ("joomla",),
}

SPA_STACK_HINTS: tuple[str, ...] = ("nextjs", "react", "nodejs", "angular", "vue")
SPA_STACK_HINTS_SET = frozenset(SPA_STACK_HINTS)

# CMS confidence at/above this level overrides SPA ``incompatible_when`` gating.
CMS_STRONG_CONFIDENCE = 0.55
# CMS hint + confidence at/above this level also overrides (headless/decoupled CMS).
CMS_HINT_BACKED_CONFIDENCE = 0.40
# Block CMS modules on SPA targets only when CMS confidence stays below this.
CMS_WEAK_SPA_BLOCK_THRESHOLD = 0.45


def cms_key_for_module_path(module_path: str) -> Optional[str]:
    low = str(module_path or "").lower()
    for cms, tokens in CMS_PATH_TOKENS.items():
        if any(token in low for token in tokens):
            return cms
    return None


def cms_stack_confidence(kb: Mapping[str, Any], cms: str) -> float:
    if not isinstance(kb, dict):
        return 0.0
    conf = kb.get("tech_confidence", {}) or {}
    try:
        return float(conf.get(str(cms).lower(), 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def strong_cms_overrides_spa(kb: Mapping[str, Any], cms: str) -> bool:
    """
    Strong CMS evidence wins over SPA hints (modern WP with React, decoupled Drupal, …).
    """
    conf = cms_stack_confidence(kb, cms)
    if conf >= CMS_STRONG_CONFIDENCE:
        return True
    if not isinstance(kb, dict):
        return False
    hints = {str(h).lower() for h in kb.get("tech_hints", []) or []}
    return cms in hints and conf >= CMS_HINT_BACKED_CONFIDENCE


def spa_incompatibility_applies(kb: Mapping[str, Any], cms: str) -> bool:
    """Return True when SPA hints should block a CMS-targeted module."""
    if strong_cms_overrides_spa(kb, cms):
        return False
    if not isinstance(kb, dict):
        return False
    hints = {str(h).lower() for h in kb.get("tech_hints", []) or []}
    if not hints.intersection(SPA_STACK_HINTS_SET):
        return False
    return cms_stack_confidence(kb, cms) < CMS_WEAK_SPA_BLOCK_THRESHOLD


def infer_stack_gate_for_path(module_path: str) -> Dict[str, Any]:
    """Default ``requires`` / ``incompatible_when`` from module path when not declared."""
    low = str(module_path or "").lower()
    if not low:
        return {}

    if "nextjs" in low or "/next.js" in low:
        return {
            "requires": {
                "tech_hints_any": ["nextjs", "nodejs", "react"],
                "confidence_min_any": {"nextjs": 0.45, "nodejs": 0.4, "react": 0.4},
            },
            "incompatible_when": {
                "tech_hints_any": ["wordpress", "drupal", "joomla"],
            },
        }

    for cms, tokens in CMS_PATH_TOKENS.items():
        if any(token in low for token in tokens):
            floor = 0.65 if low.startswith("exploits/") else 0.3
            return {
                "requires": {
                    "confidence_min": {cms: floor},
                },
                "incompatible_when": {
                    "tech_hints_any": list(SPA_STACK_HINTS),
                },
            }
    return {}


def merge_agent_gate_blocks(
    explicit: Optional[Mapping[str, Any]],
    inferred: Optional[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Merge inferred gates into explicit ``agent`` block (explicit wins on conflicts)."""
    if not explicit and not inferred:
        return None
    out: Dict[str, Any] = dict(explicit or {})
    inf = inferred if isinstance(inferred, dict) else {}
    for key in ("requires", "incompatible_when"):
        base = dict(out.get(key) or {})
        extra = dict(inf.get(key) or {})
        for field, value in extra.items():
            if field not in base or not base.get(field):
                base[field] = value
        if base:
            out[key] = base
    return out or None


def _drop_spa_incompatibility_for_cms_override(
    gate: Optional[Mapping[str, Any]],
    kb: Mapping[str, Any],
    module_path: str,
) -> Optional[Dict[str, Any]]:
    """Allow strong CMS evidence to coexist with modern JS frontend hints."""
    if not gate:
        return None
    cms = cms_key_for_module_path(module_path)
    if not cms or not strong_cms_overrides_spa(kb, cms):
        return dict(gate)

    out: Dict[str, Any] = dict(gate)
    inc = dict(out.get("incompatible_when") or {})
    tech_any = inc.get("tech_hints_any")
    if isinstance(tech_any, (list, tuple, set)):
        remaining = [
            str(token)
            for token in tech_any
            if str(token).lower() not in SPA_STACK_HINTS_SET
        ]
        if remaining:
            inc["tech_hints_any"] = remaining
        else:
            inc.pop("tech_hints_any", None)
    if inc:
        out["incompatible_when"] = inc
    else:
        out.pop("incompatible_when", None)
    return out or None


def _legacy_cms_stack_mismatch(
    module_path: str,
    kb: Dict[str, Any],
    *,
    has_tech_evidence: Optional[Callable[[str, float], bool]] = None,
    has_nextjs_evidence: Optional[Callable[[], bool]] = None,
) -> str:
    del has_tech_evidence, has_nextjs_evidence
    cms = cms_key_for_module_path(module_path)
    if not cms or not isinstance(kb, dict):
        return ""
    if not spa_incompatibility_applies(kb, cms):
        return ""
    return (
        f"stack mismatch: `{cms}` module without strong {cms} evidence "
        "on probable modern JS app"
    )


def resolve_module_stack_mismatch(
    module_path: str,
    kb: Dict[str, Any],
    agent: Optional[Mapping[str, Any]] = None,
    *,
    has_tech_evidence: Optional[Callable[[str, float], bool]] = None,
    has_nextjs_evidence: Optional[Callable[[], bool]] = None,
) -> str:
    """
    Return a human-readable skip reason, or ``""`` if the module may run.

    Order: merged declarative gates → legacy CMS path heuristic.
    """
    if not isinstance(kb, dict):
        return ""

    inferred = infer_stack_gate_for_path(module_path)
    merged = merge_agent_gate_blocks(agent, inferred)
    merged = _drop_spa_incompatibility_for_cms_override(merged, kb, module_path)
    if merged:
        if not module_matches_state(merged, kb, module_path=module_path):
            return module_mismatch_reason(merged, kb, module_path=module_path) or "module prerequisites not satisfied"
        return ""

    return _legacy_cms_stack_mismatch(
        module_path,
        kb,
        has_tech_evidence=has_tech_evidence,
        has_nextjs_evidence=has_nextjs_evidence,
    )
