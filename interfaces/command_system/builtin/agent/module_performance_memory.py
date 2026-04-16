#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Persistent memory of scanner module outcomes per target profile (data-driven utility tuning).

Complements ``history_scores.json`` (finding-centric FP heuristics) with **module rentability**:
executed path, target context, estimated cost, KB deltas, exploit links, FP-like signals.

File: ``reports/agent/module_performance.json``
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from interfaces.command_system.builtin.agent.io_utils import atomic_write_json, load_json_dict
from interfaces.command_system.builtin.agent.module_scoring import estimate_network_cost, information_score_kb

MAX_RECORDS = 2000
FILE_NAME = "module_performance.json"


def classify_target_profile(kb: Dict[str, Any]) -> str:
    """
    Compact context key for aggregation, e.g. ``drupal+wordpress_login`` or ``unknown_nologin``.
    """
    if not isinstance(kb, dict):
        return "unknown_unknown"
    conf = kb.get("tech_confidence", {}) or {}
    tags: List[str] = []
    for name in ("wordpress", "drupal", "joomla"):
        try:
            if float(conf.get(name, 0) or 0) >= 0.45:
                tags.append(name[:5])
        except Exception:
            continue
    if not tags:
        for name in ("wordpress", "drupal", "joomla"):
            for h in kb.get("tech_hints", []) or []:
                if name in str(h).lower():
                    tags.append(name[:5])
                    break
    stack = "+".join(sorted(set(tags))) or "unknown"
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if "authenticated_session" in signals:
        auth = "session"
    elif signals.intersection({
        "login_redirect_detected",
        "login_form_detected",
        "login_surface_detected",
    }):
        auth = "login"
    else:
        auth = "nologin"
    return f"{stack}_{auth}"


def kb_metrics_snapshot(kb: Dict[str, Any]) -> Dict[str, float]:
    if not isinstance(kb, dict):
        return {"endpoints": 0.0, "params": 0.0, "info": 0.0}
    return {
        "endpoints": float(len(kb.get("discovered_endpoints", []) or [])),
        "params": float(len(kb.get("discovered_params", []) or [])),
        "info": float(information_score_kb(kb)),
    }


def kb_light_copy(kb: Dict[str, Any]) -> Dict[str, Any]:
    """Shallow copy of KB fields used for metrics and :func:`classify_target_profile` (before a phase runs)."""
    if not isinstance(kb, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in (
        "discovered_endpoints",
        "discovered_params",
        "tech_hints",
        "specializations",
        "tech_confidence",
        "risk_signals",
        "login_paths",
    ):
        val = kb.get(key)
        if isinstance(val, list):
            out[key] = list(val)
        elif isinstance(val, dict):
            out[key] = dict(val)
        else:
            out[key] = val
    return out


class ModulePerformanceMemory:
    """Load/save rolling records and expose utility multipliers for :func:`module_utility`."""

    def __init__(self) -> None:
        self._path = os.path.join(os.getcwd(), "reports", "agent", FILE_NAME)
        self._records: List[Dict[str, Any]] = []
        # (module_path, profile) -> {count, sum_reward}
        self._agg: Dict[Tuple[str, str], Dict[str, float]] = {}
        self._agg_path_only: Dict[str, Dict[str, float]] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = load_json_dict(self._path)
            if not isinstance(data, dict):
                return
            recs = data.get("records", [])
            self._records = recs if isinstance(recs, list) else []
            self._rebuild_aggregates()
        except Exception:
            self._records = []

    def _rebuild_aggregates(self) -> None:
        self._agg.clear()
        self._agg_path_only.clear()
        for row in self._records:
            if not isinstance(row, dict):
                continue
            path = str(row.get("module_path", "") or "")
            prof = str(row.get("target_profile", "") or "")
            r = float(row.get("reward", 0) or 0)
            if path:
                self._bump(self._agg_path_only, path, r)
            if path and prof:
                key = (path, prof)
                self._bump_dict(self._agg, key, r)

    @staticmethod
    def _bump(store: Dict[str, Dict[str, float]], path: str, reward: float) -> None:
        ent = store.get(path)
        if not ent:
            ent = {"count": 0.0, "sum_reward": 0.0}
            store[path] = ent
        ent["count"] += 1.0
        ent["sum_reward"] += reward

    @staticmethod
    def _bump_dict(
        store: Dict[Tuple[str, str], Dict[str, float]],
        key: Tuple[str, str],
        reward: float,
    ) -> None:
        ent = store.get(key)
        if not ent:
            ent = {"count": 0.0, "sum_reward": 0.0}
            store[key] = ent
        ent["count"] += 1.0
        ent["sum_reward"] += reward

    def _save(self) -> None:
        payload = {
            "version": 1,
            "updated_at": datetime.now().isoformat(),
            "records": self._records[-MAX_RECORDS:],
        }
        try:
            atomic_write_json(self._path, payload)
        except Exception:
            pass

    @staticmethod
    def _compute_reward(
        share_ep: float,
        share_params: float,
        delta_info: float,
        vulnerable: bool,
        exploit_link: bool,
        likely_fp: bool,
        cost: float,
    ) -> float:
        gain = (
            share_ep * 1.1
            + share_params * 1.35
            + max(0.0, delta_info) * 0.5
            + (2.1 if vulnerable else 0.0)
            + (1.15 if exploit_link else 0.0)
        )
        if likely_fp:
            gain -= 1.85
        return gain / max(0.45, cost)

    def record_phase_results(
        self,
        kb_before: Dict[str, Any],
        kb_after: Dict[str, Any],
        phase_results: List[Dict[str, Any]],
        phase_name: str,
        hostname: str,
        is_actionable: Callable[[Dict[str, Any]], bool],
        has_exploit_link: Callable[[Dict[str, Any]], bool],
    ) -> None:
        """
        Call after ``_update_knowledge_base_from_results`` so ``kb_after`` matches persisted KB.
        Splits endpoint/param/info deltas evenly across modules in the batch (approximation).
        """
        if not phase_results:
            return
        b = kb_metrics_snapshot(kb_before)
        a = kb_metrics_snapshot(kb_after)
        d_ep = max(0.0, a["endpoints"] - b["endpoints"])
        d_pa = max(0.0, a["params"] - b["params"])
        d_info = a["info"] - b["info"]
        n = max(1, len(phase_results))
        share_ep = d_ep / n
        share_pa = d_pa / n
        share_info = d_info / n
        profile = classify_target_profile(kb_after if isinstance(kb_after, dict) else kb_before)

        ts = datetime.now().isoformat()
        for row in phase_results:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            if not path:
                continue
            cost = float(estimate_network_cost(path.lower()))
            vuln = bool(row.get("vulnerable"))
            actionable = bool(is_actionable(row))
            likely_fp = vuln and not actionable
            ex_link = bool(has_exploit_link(row))
            reward = self._compute_reward(
                share_ep,
                share_pa,
                share_info,
                vuln,
                ex_link,
                likely_fp,
                cost,
            )
            record = {
                "ts": ts,
                "phase": phase_name,
                "host": (hostname or "")[:200],
                "module_path": path[:300],
                "target_profile": profile[:120],
                "estimated_cost": round(cost, 3),
                "delta_endpoints": round(share_ep, 4),
                "delta_params": round(share_pa, 4),
                "delta_kb_info": round(share_info, 4),
                "vulnerable": vuln,
                "actionable": actionable,
                "likely_false_positive": likely_fp,
                "exploit_link_in_result": ex_link,
                "reward": round(reward, 4),
            }
            self._records.append(record)
            self._bump_dict(self._agg, (path, profile), reward)
            self._bump(self._agg_path_only, path, reward)

        if len(self._records) > MAX_RECORDS * 2:
            self._records = self._records[-MAX_RECORDS:]
        self._save()

    def utility_multiplier(self, module_path: str, kb: Dict[str, Any]) -> float:
        """
        Blend profile-specific and path-only historical reward (needs a few samples).
        Returns ~1.0 when data is insufficient.
        """
        if not module_path:
            return 1.0
        profile = classify_target_profile(kb if isinstance(kb, dict) else {})
        m_prof = self._mult_for_key(self._agg.get((module_path, profile)))
        m_any = self._mult_for_key_path(module_path)
        ent_prof = self._agg.get((module_path, profile))
        c_prof = int((ent_prof or {}).get("count", 0) or 0)
        ent_any = self._agg_path_only.get(module_path)
        c_any = int((ent_any or {}).get("count", 0) or 0)
        if c_prof < 2 and c_any < 3:
            return 1.0
        if c_prof >= 3:
            w = min(1.0, c_prof / 8.0)
            return m_prof * w + m_any * (1.0 - w)
        return m_any

    @staticmethod
    def _mult_for_key(ent: Optional[Dict[str, float]]) -> float:
        if not ent:
            return 1.0
        c = float(ent.get("count", 0) or 0)
        if c < 1.0:
            return 1.0
        avg = float(ent.get("sum_reward", 0) or 0) / c
        # Typical avg in [-1, 4]; map to multiplier band
        return max(0.72, min(1.28, 1.0 + max(-0.35, min(0.35, avg * 0.11))))

    def _mult_for_key_path(self, module_path: str) -> float:
        ent = self._agg_path_only.get(module_path)
        return self._mult_for_key(ent)
