#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shared module metadata normalization and weighted token scoring for campaign selection.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

# Rules: (weight, token_tuple) — score += weight if any token appears in blob (substring match).
ModuleScoreRules = List[Tuple[int, Tuple[str, ...]]]


def information_score_kb(kb: Dict[str, Any]) -> float:
    """
    Scalar summary of how much the knowledge base has grown (telemetry / stop trends).
    Kept here (not in ``campaign_utility``) to avoid circular imports with ``module_state_match``.
    """
    if not isinstance(kb, dict):
        return 0.0
    endpoints = kb.get("discovered_endpoints", []) or []
    params = kb.get("discovered_params", []) or []
    hints = kb.get("tech_hints", []) or []
    signals = kb.get("risk_signals", []) or []
    login_paths = kb.get("login_paths", []) or []
    return (
        min(40.0, len(endpoints) * 0.12)
        + min(20.0, len(params) * 0.06)
        + min(15.0, len(hints) * 0.35)
        + min(12.0, len(signals) * 0.25)
        + min(8.0, len(login_paths) * 0.4)
    )


def estimate_network_cost(path_lower: str) -> float:
    """Higher ≈ more HTTP volume / slower modules (rough ordinal scale)."""
    cost = 1.0
    if "crawler" in path_lower:
        cost += 3.8
    if "fuzzer" in path_lower or "fuzz" in path_lower:
        cost += 2.8
    if any(x in path_lower for x in ("wordpress_scanner", "drupal_scanner", "joomla_scanner")):
        cost += 2.2
    if "bruteforce" in path_lower:
        cost += 2.0
    if "smuggling" in path_lower:
        cost += 1.5
    if "_detect" in path_lower or "server_banner" in path_lower or "banner" in path_lower:
        cost -= 0.45
    return max(0.4, cost)


def module_path_lower(module: Dict) -> str:
    return str(module.get("path", "") or "").lower()


def module_blob_lower(module: Dict) -> str:
    """Single lowercased blob: path, name, description, tags (hot-path friendly)."""
    path = module_path_lower(module)
    name = str(module.get("name", "") or "").lower()
    desc = str(module.get("description", "") or "").lower()
    tags = module.get("tags", []) or []
    tag_part = " ".join(str(t).lower() for t in tags)
    return f"{path} {name} {desc} {tag_part}".strip()


def score_rules(blob: str, rules: Sequence[Tuple[int, Tuple[str, ...]]]) -> int:
    return sum(w for w, tokens in rules if any(t in blob for t in tokens))


def score_tech_hints_in_blob(blob: str, tech_hints: Sequence[str], weight: int = 4) -> int:
    """Each hint that appears in blob adds ``weight`` (matches prior per-hint scoring)."""
    return weight * sum(1 for h in tech_hints if h and h in blob)
