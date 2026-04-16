#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Learn which scanner modules pay off in which **operational contexts** (not target hostname).

Persisted at ``reports/agent/module_context_memory.json``::

    {
      "version": 2,
      "contexts": {
        "login_detected_no_auth": {
          "admin_login_bruteforce": {"score": 0.9, "n": 12},
          "spa_scanner": {"score": 0.2, "n": 8}
        },
        "authenticated_session": { ... }
      }
    }

Keys are module **basenames** (last segment of ``auxiliary/.../path``). Used as a multiplier on
:class:`~.module_performance_memory.ModulePerformanceMemory` / :func:`campaign_utility.module_utility`.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from interfaces.command_system.builtin.agent.agent_constants import DEFAULT_MODULE_CONTEXT_PRIORS
from interfaces.command_system.builtin.agent.io_utils import atomic_write_json, load_json_dict
from interfaces.command_system.builtin.agent.module_performance_memory import (
    ModulePerformanceMemory,
    kb_metrics_snapshot,
)
from interfaces.command_system.builtin.agent.module_scoring import estimate_network_cost

FILE_NAME = "module_context_memory.json"
MAX_CONTEXTS = 48
ALPHA_MAX = 0.28

# Ordered checks are done in :func:`classify_operational_context`
CONTEXT_AUTHENTICATED = "authenticated_session"
CONTEXT_LOGIN_NO_AUTH = "login_detected_no_auth"
CONTEXT_CMS_LOCKED = "cms_stack_locked"
CONTEXT_COLD_RECON = "cold_recon"

_CMS_SPECS = frozenset({"wordpress", "drupal", "joomla"})


def module_basename(module_path: str) -> str:
    p = (module_path or "").strip().rstrip("/")
    if not p:
        return ""
    return p.split("/")[-1].lower()


def classify_operational_context(kb: Dict[str, Any]) -> str:
    """
    Single high-level context for learning and scoring.

    Priority: authenticated → login surface without session → CMS identified → default recon.
    """
    if not isinstance(kb, dict):
        return CONTEXT_COLD_RECON
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if "authenticated_session" in signals:
        return CONTEXT_AUTHENTICATED

    login_paths = kb.get("login_paths", []) or []
    has_path = any(isinstance(p, str) and p.startswith("/") for p in login_paths)
    login_signals = signals.intersection({
        "login_redirect_detected",
        "login_form_detected",
        "login_surface_detected",
    })
    if (has_path or login_signals) and "authenticated_session" not in signals:
        return CONTEXT_LOGIN_NO_AUTH

    specs = {str(x).lower() for x in kb.get("specializations", []) or []}
    if specs & _CMS_SPECS:
        return CONTEXT_CMS_LOCKED

    conf = kb.get("tech_confidence", {}) or {}
    for name in _CMS_SPECS:
        try:
            if float(conf.get(name, 0) or 0) >= 0.52:
                return CONTEXT_CMS_LOCKED
        except Exception:
            continue

    return CONTEXT_COLD_RECON


def _reward_to_unit_interval(reward: float) -> float:
    """Map performance reward (roughly -2..6) to 0..1 for EMA."""
    try:
        r = float(reward)
    except Exception:
        r = 0.0
    return max(0.0, min(1.0, 0.42 + 0.11 * r))


class ModuleContextMemory:
    """EMA scores per (context, module_basename); blends with optional priors."""

    def __init__(self) -> None:
        self._path = os.path.join(os.getcwd(), "reports", "agent", FILE_NAME)
        self._contexts: Dict[str, Dict[str, Dict[str, float]]] = {}
        self._priors: Dict[str, Dict[str, float]] = dict(DEFAULT_MODULE_CONTEXT_PRIORS)
        self._load()

    def _load(self) -> None:
        try:
            data = load_json_dict(self._path)
            if not isinstance(data, dict):
                return
            ctx = data.get("contexts", {})
            if isinstance(ctx, dict):
                self._contexts = self._sanitize_contexts(ctx)
        except Exception:
            self._contexts = {}

    @staticmethod
    def _sanitize_contexts(raw: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, float]]]:
        out: Dict[str, Dict[str, Dict[str, float]]] = {}
        for ck, cv in list(raw.items())[:MAX_CONTEXTS]:
            if not isinstance(ck, str) or not isinstance(cv, dict):
                continue
            inner: Dict[str, Dict[str, float]] = {}
            for mk, mv in cv.items():
                if not isinstance(mk, str):
                    continue
                key = mk.lower()
                if isinstance(mv, dict):
                    sc = mv.get("score", 0.5)
                    n = mv.get("n", 0)
                elif isinstance(mv, (int, float)):
                    sc, n = float(mv), 1.0
                else:
                    continue
                try:
                    inner[key] = {"score": max(0.0, min(1.0, float(sc))), "n": max(0.0, float(n))}
                except Exception:
                    continue
            if inner:
                out[ck] = inner
        return out

    def _save(self) -> None:
        payload = {
            "version": 2,
            "updated_at": datetime.now().isoformat(),
            "contexts": self._contexts,
        }
        try:
            atomic_write_json(self._path, payload)
        except Exception:
            pass

    def _prior_score(self, context: str, base: str) -> Optional[float]:
        row = self._priors.get(context) or {}
        v = row.get(base)
        if v is None:
            return None
        try:
            return max(0.0, min(1.0, float(v)))
        except Exception:
            return None

    @staticmethod
    def _score_to_multiplier(score: float) -> float:
        """Map 0..1 learned utility into a multiplier band around 1.0."""
        try:
            s = float(score)
        except Exception:
            s = 0.5
        s = max(0.0, min(1.0, s))
        return max(0.58, min(1.22, 0.72 + 0.48 * s))

    def context_multiplier(self, module_path: str, kb: Dict[str, Any]) -> float:
        """
        Returns ~1.0 when unknown; up-weight modules that historically paid off in this context.
        """
        base = module_basename(module_path)
        if not base:
            return 1.0
        ctx = classify_operational_context(kb if isinstance(kb, dict) else {})
        row = (self._contexts.get(ctx) or {}).get(base)
        prior = self._prior_score(ctx, base)
        if row:
            n = float(row.get("n", 0) or 0)
            sc = float(row.get("score", 0.5) or 0.5)
            # Few samples: blend toward neutral and prior
            w = min(1.0, n / 5.0)
            neutral = 1.0
            blended = sc * w + neutral * (1.0 - w)
            if prior is not None and n < 4.0:
                blended = blended * 0.65 + prior * 0.35
            return self._score_to_multiplier(blended)
        if prior is not None:
            return self._score_to_multiplier(prior)
        return 1.0

    def record_phase_results(
        self,
        kb_before: Dict[str, Any],
        kb_after: Dict[str, Any],
        phase_results: List[Dict[str, Any]],
        phase_name: str,
        is_actionable: Callable[[Dict[str, Any]], bool],
        has_exploit_link: Callable[[Dict[str, Any]], bool],
    ) -> None:
        """Call after KB update; learns from the operational context **before** the phase."""
        if not phase_results:
            return
        b = kb_metrics_snapshot(kb_before if isinstance(kb_before, dict) else {})
        a = kb_metrics_snapshot(kb_after if isinstance(kb_after, dict) else {})
        d_ep = max(0.0, a["endpoints"] - b["endpoints"])
        d_pa = max(0.0, a["params"] - b["params"])
        d_info = a["info"] - b["info"]
        n_mod = max(1, len(phase_results))
        share_ep = d_ep / n_mod
        share_pa = d_pa / n_mod
        share_info = d_info / n_mod

        ctx = classify_operational_context(kb_before if isinstance(kb_before, dict) else {})

        for row in phase_results:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            if not path:
                continue
            base = module_basename(path)
            if not base:
                continue
            cost = float(estimate_network_cost(path.lower()))
            vuln = bool(row.get("vulnerable"))
            actionable = bool(is_actionable(row))
            likely_fp = vuln and not actionable
            ex_link = bool(has_exploit_link(row))
            reward = ModulePerformanceMemory._compute_reward(
                share_ep,
                share_pa,
                share_info,
                vuln,
                ex_link,
                likely_fp,
                cost,
            )
            outcome = _reward_to_unit_interval(reward)
            self._ema_update(ctx, base, outcome)

        self._save()

    def _ema_update(self, context: str, base: str, outcome: float) -> None:
        ctx_map = self._contexts.setdefault(context, {})
        ent = ctx_map.get(base)
        prior = self._prior_score(context, base)
        if not ent:
            init = float(prior) if prior is not None else 0.5
            ent = {"score": max(0.0, min(1.0, init)), "n": 0.0}
        n = float(ent.get("n", 0) or 0) + 1.0
        alpha = min(ALPHA_MAX, 1.0 / max(1.0, n ** 0.5))
        old = float(ent.get("score", 0.5) or 0.5)
        new_score = alpha * outcome + (1.0 - alpha) * old
        ent["score"] = max(0.0, min(1.0, new_score))
        ent["n"] = n
        ctx_map[base] = ent
