#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Track module failures per stack/target profile and deprioritize repeat dead ends.

Examples persisted:
- ``exploits/http/drupal_rce`` + ``unknown_nologin`` + ``stack_mismatch`` (Next.js target)
- ``admin_login_bruteforce`` + ``wordpress_login`` + ``bad_path``
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from interfaces.command_system.builtin.agent.io_utils import atomic_write_json, load_json_dict
from interfaces.command_system.builtin.agent.module_performance_memory import classify_target_profile
from interfaces.command_system.builtin.agent.module_stack_gate import resolve_module_stack_mismatch
from interfaces.command_system.builtin.agent.run_store import AgentPathService

logger = logging.getLogger(__name__)

FILE_NAME = "module_health.json"
MAX_RECORDS = 2500

_STACK_MISMATCH_RE = re.compile(r"stack mismatch|incompatible:", re.I)
_BAD_LOGIN_RE = re.compile(
    r"no valid|no credential|exhausted|could not find|unable to reach login|login page not",
    re.I,
)


def classify_module_failure(
    row: Dict[str, Any],
    *,
    kb: Optional[Dict[str, Any]] = None,
    is_actionable: Optional[Callable[[Dict[str, Any]], bool]] = None,
    stack_mismatch_reason: str = "",
    novelty_zero: bool = False,
) -> Optional[str]:
    """Return failure kind token or ``None`` if outcome is neutral/positive."""
    if not isinstance(row, dict):
        return None
    path = str(row.get("path", "") or "").lower()
    msg = str(row.get("message", "") or "")
    status = str(row.get("status", "") or "").lower()
    blob = f"{msg} {stack_mismatch_reason}".lower()

    if stack_mismatch_reason or _STACK_MISMATCH_RE.search(blob):
        return "stack_mismatch"
    if status == "skipped" and any(
        tok in blob for tok in ("approval", "profile blocks", "requires explicit")
    ):
        return "skipped_policy"
    if "admin_login_bruteforce" in path and _BAD_LOGIN_RE.search(msg):
        return "bad_path"
    if status == "error":
        return "error"
    actionable = bool(is_actionable(row)) if is_actionable else bool(row.get("vulnerable"))
    if row.get("vulnerable") and not actionable:
        return "false_positive"
    if novelty_zero and status not in ("skipped", "error") and not actionable:
        if any(tok in path for tok in ("exploit", "drupal", "wordpress", "joomla", "bruteforce")):
            return "no_signal"
    return None


class ModuleHealthMemory:
    """Rolling failure memory keyed by (module_path, target_profile, failure_kind)."""

    def __init__(self, paths: Optional[AgentPathService] = None) -> None:
        self._paths = paths or AgentPathService()
        self._paths.ensure()
        self._path = str(self._paths.memory_dir / FILE_NAME)
        self._records: List[Dict[str, Any]] = []
        self._agg: Dict[Tuple[str, str, str], Dict[str, float]] = {}
        self._path_profile: Dict[Tuple[str, str], Dict[str, float]] = {}
        self._load()

    def set_paths(self, paths: AgentPathService) -> None:
        self._paths = paths
        self._paths.ensure()
        self._path = str(self._paths.memory_dir / FILE_NAME)
        self._records = []
        self._agg.clear()
        self._path_profile.clear()
        self._load()

    def export_summary(self) -> Dict[str, Any]:
        return {
            "records": len(self._records),
            "aggregates": len(self._agg),
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
        self._path_profile.clear()
        for row in self._records:
            if not isinstance(row, dict):
                continue
            mod = str(row.get("module_path", "") or "")
            prof = str(row.get("target_profile", "") or "")
            kind = str(row.get("failure_kind", "") or "")
            if mod and prof and kind:
                key = (mod, prof, kind)
                ent = self._agg.setdefault(key, {"count": 0.0, "weight": 0.0})
                ent["count"] += 1.0
                ent["weight"] += float(row.get("weight", 1.0) or 1.0)
                pp = self._path_profile.setdefault((mod, prof), {"failures": 0.0, "weight": 0.0})
                pp["failures"] += 1.0
                pp["weight"] += float(row.get("weight", 1.0) or 1.0)

    def _save(self) -> None:
        payload = {
            "version": 1,
            "updated_at": datetime.now().isoformat(),
            "records": self._records[-MAX_RECORDS:],
        }
        try:
            atomic_write_json(self._path, payload)
        except Exception as exc:
            logger.warning("Could not persist module health memory: %s", exc)

    def record_failure(
        self,
        module_path: str,
        kb: Dict[str, Any],
        failure_kind: str,
        *,
        context: str = "",
        weight: float = 1.0,
        hostname: str = "",
    ) -> None:
        if not module_path or not failure_kind:
            return
        profile = classify_target_profile(kb if isinstance(kb, dict) else {})
        record = {
            "ts": datetime.now().isoformat(),
            "host": (hostname or "")[:200],
            "module_path": module_path[:300],
            "target_profile": profile[:120],
            "failure_kind": failure_kind[:64],
            "context": (context or "")[:240],
            "weight": round(float(weight), 3),
        }
        self._records.append(record)
        key = (module_path, profile, failure_kind)
        ent = self._agg.setdefault(key, {"count": 0.0, "weight": 0.0})
        ent["count"] += 1.0
        ent["weight"] += float(weight)
        pp = self._path_profile.setdefault((module_path, profile), {"failures": 0.0, "weight": 0.0})
        pp["failures"] += 1.0
        pp["weight"] += float(weight)
        if len(self._records) > MAX_RECORDS * 2:
            self._records = self._records[-MAX_RECORDS:]
            self._rebuild_aggregates()
        self._save()

    def record_phase_outcomes(
        self,
        kb_before: Dict[str, Any],
        kb_after: Dict[str, Any],
        phase_results: List[Dict[str, Any]],
        *,
        hostname: str = "",
        is_actionable: Optional[Callable[[Dict[str, Any]], bool]] = None,
        get_agent_metadata: Optional[Callable[[str], Any]] = None,
        stack_mismatch_fn: Optional[Callable[[str, Dict[str, Any]], str]] = None,
    ) -> None:
        if not phase_results:
            return
        b_ep = len((kb_before or {}).get("discovered_endpoints", []) or [])
        a_ep = len((kb_after or {}).get("discovered_endpoints", []) or [])
        b_pa = len((kb_before or {}).get("discovered_params", []) or [])
        a_pa = len((kb_after or {}).get("discovered_params", []) or [])
        novelty_zero = (a_ep - b_ep) <= 0 and (a_pa - b_pa) <= 0

        for row in phase_results:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            if not path:
                continue
            agent = get_agent_metadata(path) if get_agent_metadata else None
            mismatch = ""
            if stack_mismatch_fn:
                mismatch = stack_mismatch_fn(path, kb_before if isinstance(kb_before, dict) else {})
            elif agent is not None:
                mismatch = resolve_module_stack_mismatch(
                    path,
                    kb_before if isinstance(kb_before, dict) else {},
                    agent,
                )
            kind = classify_module_failure(
                row,
                kb=kb_after,
                is_actionable=is_actionable,
                stack_mismatch_reason=mismatch,
                novelty_zero=novelty_zero,
            )
            if not kind:
                continue
            ctx = mismatch or str(row.get("message", "") or "")[:200]
            weight = 1.35 if kind == "stack_mismatch" else 1.0
            if kind == "bad_path":
                weight = 1.2
            self.record_failure(
                path,
                kb_after if isinstance(kb_after, dict) else kb_before,
                kind,
                context=ctx,
                weight=weight,
                hostname=hostname,
            )

    def health_multiplier(self, module_path: str, kb: Dict[str, Any]) -> float:
        """
        Deprioritize modules with repeated failures on this stack/profile.

        Returns ~1.0 when unknown; floor ~0.32 for chronic mismatches.
        """
        if not module_path:
            return 1.0
        profile = classify_target_profile(kb if isinstance(kb, dict) else {})
        pp = self._path_profile.get((module_path, profile))
        if not pp:
            return 1.0
        failures = float(pp.get("failures", 0) or 0)
        weight = float(pp.get("weight", 0) or 0)
        if failures < 2.0:
            return 1.0

        stack_fails = 0.0
        for (mod, prof, kind), ent in self._agg.items():
            if mod != module_path or prof != profile:
                continue
            if kind == "stack_mismatch":
                stack_fails += float(ent.get("count", 0) or 0)

        avg_weight = weight / max(1.0, failures)
        mult = 1.0
        if failures >= 5 and avg_weight >= 1.1:
            mult = 0.32
        elif failures >= 4:
            mult = 0.45
        elif failures >= 3:
            mult = 0.58
        elif failures >= 2:
            mult = 0.72

        if stack_fails >= 2:
            mult = min(mult, 0.38)
        elif stack_fails >= 1:
            mult = min(mult, 0.55)

        return max(0.32, min(1.0, mult))

    def top_failures_for_profile(
        self,
        kb: Dict[str, Any],
        *,
        limit: int = 8,
    ) -> List[Dict[str, Any]]:
        profile = classify_target_profile(kb if isinstance(kb, dict) else {})
        rows: List[Dict[str, Any]] = []
        for (mod, prof, kind), ent in self._agg.items():
            if prof != profile:
                continue
            rows.append({
                "module_path": mod,
                "failure_kind": kind,
                "count": int(ent.get("count", 0) or 0),
            })
        rows.sort(key=lambda r: (-int(r.get("count", 0)), str(r.get("module_path", ""))))
        return rows[:limit]
