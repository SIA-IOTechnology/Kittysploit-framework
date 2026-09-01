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
import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from interfaces.command_system.builtin.agent.io_utils import atomic_write_json, load_json_dict
from interfaces.command_system.builtin.agent.module_scoring import estimate_network_cost, information_score_kb
from interfaces.command_system.builtin.agent.run_store import AgentPathService

logger = logging.getLogger(__name__)

MAX_RECORDS = 2000
FILE_NAME = "module_performance.json"
RECENT_REWARD_WINDOW = 10


# Product stacks used for quarantine profile keys and CMS-lock dominance.
# Order within a confidence tier does not matter; scores decide.
_LAB_STACK_NAMES = ("dvwa", "mutillidae", "bwapp", "webgoat", "juiceshop")
_ADMIN_STACK_NAMES = (
    "phpmyadmin", "grafana", "jenkins", "tomcat", "roundcube", "kibana",
)
_CMS_STACK_NAMES = ("wordpress", "drupal", "joomla")
_FRAMEWORK_STACK_NAMES = (
    "nextjs", "django", "flask", "fastapi", "nodejs", "react", "angular", "vue",
)
_DATA_STACK_NAMES = ("elasticsearch", "mongodb", "redis")
_PRODUCT_STACK_NAMES = (
    _LAB_STACK_NAMES
    + _ADMIN_STACK_NAMES
    + _CMS_STACK_NAMES
    + _FRAMEWORK_STACK_NAMES
    + _DATA_STACK_NAMES
)
# Non-CMS products that should suppress CMS lock when they dominate the target.
_CMS_LOCK_BLOCKERS = _LAB_STACK_NAMES + _ADMIN_STACK_NAMES + (
    "nextjs", "django", "flask", "fastapi", "nodejs",
)


def _confidence_map(kb: Dict[str, Any]) -> Dict[str, float]:
    conf = (kb or {}).get("tech_confidence", {}) or {}
    out: Dict[str, float] = {}
    for name, raw in conf.items():
        try:
            out[str(name).lower()] = float(raw or 0.0)
        except Exception:
            continue
    return out


def ranked_product_stacks(
    kb: Dict[str, Any],
    *,
    threshold: float = 0.45,
) -> List[Tuple[str, float]]:
    """Return ``(name, score)`` for known products at/above ``threshold``, highest first."""
    if not isinstance(kb, dict):
        return []
    conf = _confidence_map(kb)
    rows: List[Tuple[str, float]] = []
    for name in _PRODUCT_STACK_NAMES:
        score = conf.get(name, 0.0)
        if score >= threshold:
            rows.append((name, score))
    rows.sort(key=lambda item: (-item[1], item[0]))
    return rows


def dominant_product_stack(
    kb: Dict[str, Any],
    *,
    threshold: float = 0.45,
) -> Optional[str]:
    """Single highest-confidence known product, or ``None``."""
    rows = ranked_product_stacks(kb, threshold=threshold)
    return rows[0][0] if rows else None


def _hint_fallback_stack(kb: Dict[str, Any]) -> Optional[str]:
    hints = [str(h).lower() for h in (kb.get("tech_hints", []) or [])]
    if not hints:
        return None
    # Prefer specific lab/admin over generic CMS when only hints exist.
    for group in (_LAB_STACK_NAMES, _ADMIN_STACK_NAMES, _CMS_STACK_NAMES, _FRAMEWORK_STACK_NAMES):
        for name in group:
            if any(name in h for h in hints):
                return name
    return None


def classify_target_profile(kb: Dict[str, Any]) -> str:
    """
    Compact context key for aggregation, e.g. ``dvwa_login`` or ``grafana_nologin``.

    Uses the dominant product stack so quarantine memory does not bleed across
    unrelated products that would otherwise collapse into ``unknown_*``.
    """
    if not isinstance(kb, dict):
        return "unknown_unknown"

    ranked = ranked_product_stacks(kb, threshold=0.45)
    if ranked:
        top_name, top_score = ranked[0]
        # Keep near-ties only when both are CMS (multi-CMS rare); otherwise single tag.
        tags = [top_name[:5]]
        for name, score in ranked[1:]:
            if name in _CMS_STACK_NAMES and top_name in _CMS_STACK_NAMES and (top_score - score) <= 0.05:
                tags.append(name[:5])
            break
        # Lab/admin dominance: never mix CMS into the key.
        if top_name in _LAB_STACK_NAMES or top_name in _ADMIN_STACK_NAMES:
            tags = [top_name[:5]]
    else:
        hint = _hint_fallback_stack(kb)
        tags = [hint[:5]] if hint else []

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


def should_suppress_cms_lock(kb: Dict[str, Any], *, threshold: float = 0.7) -> bool:
    """True when a non-CMS product dominates and CMS lock would starve its modules."""
    ranked = ranked_product_stacks(kb, threshold=threshold)
    if not ranked:
        return False
    top_name, _ = ranked[0]
    return top_name in _CMS_LOCK_BLOCKERS


def cms_lock_targets(kb: Dict[str, Any], *, threshold: float = 0.7) -> set:
    """
    CMS names to hard-lock on, or empty.

    Only the dominant CMS at/above ``threshold`` — never specialization noise alone.
    """
    if should_suppress_cms_lock(kb, threshold=threshold):
        return set()
    ranked = ranked_product_stacks(kb, threshold=threshold)
    if not ranked:
        return set()
    top_name, _ = ranked[0]
    if top_name in _CMS_STACK_NAMES:
        return {top_name}
    return set()



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

    def __init__(self, paths: Optional[AgentPathService] = None) -> None:
        self._paths = paths or AgentPathService()
        self._paths.ensure()
        self._path = str(self._paths.memory_dir / FILE_NAME)
        self._records: List[Dict[str, Any]] = []
        # (module_path, profile) -> {count, sum_reward}
        self._agg: Dict[Tuple[str, str], Dict[str, float]] = {}
        self._agg_path_only: Dict[str, Dict[str, float]] = {}
        self._recent_by_path: Dict[str, Dict[str, float]] = {}
        self._load()

    def set_paths(self, paths: AgentPathService) -> None:
        self._paths = paths
        self._paths.ensure()
        self._path = str(self._paths.memory_dir / FILE_NAME)
        self._records = []
        self._agg.clear()
        self._agg_path_only.clear()
        self._recent_by_path.clear()
        self._load()

    def reset(self) -> None:
        self._records = []
        self._agg.clear()
        self._agg_path_only.clear()
        self._recent_by_path.clear()
        self._save()

    def export_summary(self) -> Dict[str, Any]:
        return {
            "records": len(self._records),
            "paths": len(self._agg_path_only),
            "profiles": len(self._agg),
            "path": self._path,
        }

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
        self._recent_by_path.clear()
        reward_windows: Dict[str, List[float]] = {}
        for row in self._records:
            if not isinstance(row, dict):
                continue
            path = str(row.get("module_path", "") or "")
            prof = str(row.get("target_profile", "") or "")
            r = float(row.get("reward", 0) or 0)
            if path:
                self._bump(self._agg_path_only, path, r)
                win = reward_windows.setdefault(path, [])
                win.append(r)
                if len(win) > RECENT_REWARD_WINDOW:
                    del win[0]
            if path and prof:
                key = (path, prof)
                self._bump_dict(self._agg, key, r)
        for path, win in reward_windows.items():
            if not win:
                continue
            neg_streak = 0
            for reward in reversed(win):
                if reward < 0:
                    neg_streak += 1
                else:
                    break
            self._recent_by_path[path] = {
                "avg_recent": float(sum(win) / max(1, len(win))),
                "neg_streak": float(neg_streak),
                "n_recent": float(len(win)),
            }

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
        except Exception as exc:
            logger.warning("Could not persist agent performance memory: %s", exc)

    @staticmethod
    def _compute_reward(
        share_ep: float,
        share_params: float,
        delta_info: float,
        vulnerable: bool,
        exploit_link: bool,
        likely_fp: bool,
        cost: float,
        novelty_zero_batch: bool = False,
        auth_gain: bool = False,
        shell_gain: bool = False,
        phase_name: str = "",
    ) -> float:
        phase = str(phase_name or "").lower()
        phase_factor = 1.0
        if phase in ("injection", "follow-up", "followup", "targeted", "adaptive", "exploit"):
            phase_factor = 1.08
        gain = (
            share_ep * 1.1
            + share_params * 1.35
            + max(0.0, delta_info) * 0.5
            + (2.1 if vulnerable else 0.0)
            + (1.15 if exploit_link else 0.0)
        )
        gain *= phase_factor
        if auth_gain:
            gain += 2.2
        if shell_gain:
            gain += 4.2
        # Penalize costly/noisy dead runs that provide no novelty and no action signal.
        if novelty_zero_batch and not vulnerable and not exploit_link:
            gain -= 1.35
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
        novelty_zero_batch = d_ep <= 0.0 and d_pa <= 0.0 and d_info <= 0.0
        before_signals = {str(s).lower() for s in (kb_before.get("risk_signals", []) if isinstance(kb_before, dict) else [])}
        after_signals = {str(s).lower() for s in (kb_after.get("risk_signals", []) if isinstance(kb_after, dict) else [])}
        auth_gain = "authenticated_session" in after_signals and "authenticated_session" not in before_signals
        shell_gain = (
            ("interactive_shell" in after_signals or "shell_obtained" in after_signals)
            and not ("interactive_shell" in before_signals or "shell_obtained" in before_signals)
        )
        weighted_rows = []
        for row in phase_results:
            if not isinstance(row, dict):
                continue
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            endpoint_count = len(
                details.get("discovered_endpoints")
                or details.get("endpoints")
                or []
            )
            param_count = len(
                details.get("discovered_params")
                or details.get("params")
                or []
            )
            evidence_weight = 1.0 + min(8.0, endpoint_count * 0.7 + param_count * 0.9)
            if bool(is_actionable(row)):
                evidence_weight += 2.0
            if bool(has_exploit_link(row)):
                evidence_weight += 1.0
            weighted_rows.append((row, evidence_weight, endpoint_count, param_count))
        total_weight = sum(item[1] for item in weighted_rows) or 1.0
        profile = classify_target_profile(kb_after if isinstance(kb_after, dict) else kb_before)

        ts = datetime.now().isoformat()
        for row, weight, endpoint_count, param_count in weighted_rows:
            path = str(row.get("path", "") or "").strip()
            if not path:
                continue
            ratio = weight / total_weight
            share_ep = min(d_ep, float(endpoint_count)) if endpoint_count else d_ep * ratio
            share_pa = min(d_pa, float(param_count)) if param_count else d_pa * ratio
            share_info = d_info * ratio
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
                novelty_zero_batch=novelty_zero_batch,
                auth_gain=auth_gain,
                shell_gain=shell_gain,
                phase_name=phase_name,
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
        recent_mult = self._recent_path_multiplier(module_path)
        if c_prof >= 3:
            w = min(1.0, c_prof / 8.0)
            base = m_prof * w + m_any * (1.0 - w)
        else:
            base = m_any
        return max(0.45, min(1.42, base * recent_mult))

    @staticmethod
    def _mult_for_key(ent: Optional[Dict[str, float]]) -> float:
        if not ent:
            return 1.0
        c = float(ent.get("count", 0) or 0)
        if c < 1.0:
            return 1.0
        avg = float(ent.get("sum_reward", 0) or 0) / c
        # Few samples stay near neutral; large samples trust contextual history more.
        sample_weight = min(1.0, c / 12.0)
        adjusted = 1.0 + (max(-0.35, min(0.35, avg * 0.11)) * sample_weight)
        return max(0.72, min(1.28, adjusted))

    def _mult_for_key_path(self, module_path: str) -> float:
        ent = self._agg_path_only.get(module_path)
        return self._mult_for_key(ent)

    def _recent_path_multiplier(self, module_path: str) -> float:
        ent = self._recent_by_path.get(module_path)
        if not ent:
            return 1.0
        avg_recent = float(ent.get("avg_recent", 0.0) or 0.0)
        neg_streak = int(ent.get("neg_streak", 0.0) or 0.0)
        n_recent = int(ent.get("n_recent", 0.0) or 0.0)
        if n_recent < 3:
            return 1.0
        if neg_streak >= 5:
            return 0.62
        if neg_streak >= 3:
            return 0.76
        if avg_recent >= 1.7:
            return 1.16
        if avg_recent >= 0.9:
            return 1.08
        if avg_recent <= -0.9:
            return 0.78
        return 1.0
