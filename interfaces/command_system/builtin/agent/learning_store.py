#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Three-tier learning store: mission (KB), target (fingerprint), global (framework)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.io_utils import atomic_write_json, load_json_dict
from interfaces.command_system.builtin.agent.learning_episode import (
    DecisionEpisode,
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    append_mission_episode,
    append_preference_pair,
    build_context_fingerprint,
    build_context_index,
    episode_from_module_result,
    is_learnable_verdict,
    mission_memory,
    retrieve_mission_episodes,
)
from interfaces.command_system.builtin.agent.learning_governance import (
    DEFAULT_RETENTION_DAYS,
    contains_secret_blob,
    purge_expired_records,
    should_record_learning,
    tenant_id,
)
from interfaces.command_system.builtin.agent.module_performance_memory import kb_metrics_snapshot
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.run_store import AgentPathService, file_lock

logger = logging.getLogger(__name__)

STORE_VERSION = 1
MAX_TARGET_EPISODES = 512
MAX_GLOBAL_EPISODES = 1200
MAX_PREFERENCES = 800
DECAY_HALF_LIFE_DAYS = 45


class LearningStore:
    """Persist verified episodes and preference pairs across mission/target/global tiers."""

    def __init__(self, paths: Optional[AgentPathService] = None) -> None:
        self._paths = paths or AgentPathService()
        self._paths.ensure()
        self._root: Optional[Path] = None
        self._global_path: Optional[Path] = None
        self._preferences_path: Optional[Path] = None

    def _ensure_root(self) -> Path:
        if self._root is not None:
            return self._root
        primary = self._paths.memory_dir / "learning"
        try:
            primary.mkdir(parents=True, exist_ok=True)
            self._root = primary
        except OSError:
            fallback = Path("artifacts") / "agent_memory" / self._paths.workspace / "learning"
            fallback.mkdir(parents=True, exist_ok=True)
            self._root = fallback
        self._global_path = self._root / "global.json"
        self._preferences_path = self._root / "preferences.json"
        return self._root

    def set_paths(self, paths: AgentPathService) -> None:
        self._paths = paths
        self._paths.ensure()
        self._root = None
        self._global_path = None
        self._preferences_path = None
        self._ensure_root()

    def _target_path(self, fingerprint: str, tenant: str) -> Path:
        root = self._ensure_root()
        safe_fp = "".join(ch for ch in fingerprint if ch.isalnum() or ch in {"_", "-", ":"})[:48]
        safe_tenant = "".join(ch for ch in tenant if ch.isalnum() or ch in {"_", "-", "."})[:48]
        return root / f"target_{safe_tenant}_{safe_fp}.json"

    @staticmethod
    def _load_json(path: Path) -> Dict[str, Any]:
        data = load_json_dict(path)
        return data if isinstance(data, dict) else {}

    def _save_json(self, path: Path, payload: Dict[str, Any]) -> None:
        atomic_write_json(str(path), payload)

    def _decayed_weight(self, recorded_at: str) -> float:
        if not recorded_at:
            return 1.0
        try:
            parsed = datetime.fromisoformat(recorded_at.replace("Z", "+00:00"))
            age_days = max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds() / 86400.0)
        except ValueError:
            return 1.0
        if DECAY_HALF_LIFE_DAYS <= 0:
            return 1.0
        return 0.5 ** (age_days / DECAY_HALF_LIFE_DAYS)

    def record_phase_results(
        self,
        state: Any,
        kb_before: Mapping[str, Any],
        kb_after: Mapping[str, Any],
        phase_results: Sequence[Mapping[str, Any]],
        phase_name: str,
        *,
        get_agent_metadata: Optional[Callable[[str], Mapping[str, Any]]] = None,
        rejected_alternatives: Optional[Sequence[Mapping[str, Any]]] = None,
        chosen_path: str = "",
    ) -> int:
        if not should_record_learning(state):
            return 0
        recorded = 0
        tenant = tenant_id(state)
        kb = getattr(state, "knowledge_base", None)
        if not isinstance(kb, dict):
            return 0
        b_metrics = kb_metrics_snapshot(kb_before if isinstance(kb_before, Mapping) else {})
        a_metrics = kb_metrics_snapshot(kb_after if isinstance(kb_after, Mapping) else {})
        delta_info = a_metrics.get("info", 0.0) - b_metrics.get("info", 0.0)
        meta_fn = get_agent_metadata or (lambda _path: {})
        for row in phase_results or []:
            if not isinstance(row, Mapping):
                continue
            path = str(row.get("path") or "").strip()
            if not path:
                continue
            episode = episode_from_module_result(
                state,
                row,
                phase=phase_name,
                agent_meta=meta_fn(path),
                tenant_id=tenant,
            )
            if episode is None:
                continue
            episode.real_gain = self._compute_gain(episode.verdict, row, delta_info=delta_info)
            if self._persist_episode(state, episode):
                recorded += 1
        if chosen_path and rejected_alternatives:
            self.record_preferences(
                state,
                chosen_path=chosen_path,
                rejected_alternatives=rejected_alternatives,
                outcome="phase_batch",
            )
        return recorded

    @staticmethod
    def _compute_gain(verdict: str, result: Mapping[str, Any], *, delta_info: float) -> float:
        from interfaces.command_system.builtin.agent.learning_episode import compute_real_gain

        return compute_real_gain(
            verdict=verdict,
            vulnerable=bool(result.get("vulnerable")),
            delta_info=delta_info,
        )

    def _persist_episode(self, state: Any, episode: DecisionEpisode) -> bool:
        if not episode.learnable:
            return False
        payload = episode.to_dict()
        if contains_secret_blob(str(payload)):
            return False
        kb = getattr(state, "knowledge_base", None)
        if isinstance(kb, dict):
            append_mission_episode(kb, episode)
        self._append_target_episode(episode.tenant_id, episode.context_fingerprint, payload)
        self._append_global_episode(episode.tenant_id, payload)
        self._update_bandit_stats(episode)
        return True

    def record_preferences(
        self,
        state: Any,
        *,
        chosen_path: str,
        rejected_alternatives: Sequence[Mapping[str, Any]],
        outcome: str = "decision",
    ) -> int:
        if not should_record_learning(state):
            return 0
        kb = getattr(state, "knowledge_base", None)
        if not isinstance(kb, dict):
            return 0
        index = build_context_index(state, kb)
        fingerprint = build_context_fingerprint(index)
        tenant = tenant_id(state)
        count = 0
        for alt in rejected_alternatives or []:
            if not isinstance(alt, Mapping):
                continue
            rejected_path = str(alt.get("path") or "").strip()
            if not rejected_path or rejected_path == chosen_path:
                continue
            append_preference_pair(
                kb,
                context_fingerprint=fingerprint,
                chosen_path=chosen_path,
                rejected_path=rejected_path,
                outcome=outcome,
                tenant_id=tenant,
            )
            self._append_preference_record({
                "context_fingerprint": fingerprint,
                "context_index": index,
                "chosen_path": chosen_path,
                "rejected_path": rejected_path,
                "outcome": outcome,
                "tenant_id": tenant,
            })
            count += 1
        return count

    def _append_target_episode(self, tenant: str, fingerprint: str, episode: Dict[str, Any]) -> None:
        path = self._target_path(fingerprint, tenant)
        with file_lock(path.with_suffix(".lock")):
            data = self._load_json(path)
            episodes = list(data.get("episodes") or [])
            episodes.append(episode)
            episodes = purge_expired_records(episodes, retention_days=DEFAULT_RETENTION_DAYS)
            payload = sanitize_nested({
                "version": STORE_VERSION,
                "tenant_id": tenant,
                "context_fingerprint": fingerprint,
                "episodes": episodes[-MAX_TARGET_EPISODES:],
                "bandit": data.get("bandit") if isinstance(data.get("bandit"), dict) else {},
            })
            self._save_json(path, payload)

    def _append_global_episode(self, tenant: str, episode: Dict[str, Any]) -> None:
        self._ensure_root()
        with file_lock(self._global_path.with_suffix(".lock")):
            data = self._load_json(self._global_path)
            episodes = list(data.get("episodes") or [])
            episodes.append({**episode, "tenant_id": tenant})
            episodes = purge_expired_records(episodes, retention_days=DEFAULT_RETENTION_DAYS)
            payload = sanitize_nested({
                "version": STORE_VERSION,
                "episodes": episodes[-MAX_GLOBAL_EPISODES:],
            })
            self._save_json(self._global_path, payload)

    def _append_preference_record(self, row: Dict[str, Any]) -> None:
        self._ensure_root()
        with file_lock(self._preferences_path.with_suffix(".lock")):
            data = self._load_json(self._preferences_path)
            rows = list(data.get("preferences") or [])
            rows.append(sanitize_nested(row))
            rows = purge_expired_records(rows, retention_days=DEFAULT_RETENTION_DAYS)
            payload = sanitize_nested({
                "version": STORE_VERSION,
                "preferences": rows[-MAX_PREFERENCES:],
            })
            self._save_json(self._preferences_path, payload)

    def _update_bandit_stats(self, episode: DecisionEpisode) -> None:
        path = self._target_path(episode.context_fingerprint, episode.tenant_id)
        with file_lock(path.with_suffix(".lock")):
            data = self._load_json(path)
            bandit = data.get("bandit") if isinstance(data.get("bandit"), dict) else {}
            key = episode.action_path
            row = dict(bandit.get(key) or {"successes": 0.0, "failures": 0.0, "samples": 0.0})
            weight = self._decayed_weight(episode.recorded_at)
            if episode.verdict == VERDICT_CONFIRMED:
                row["successes"] = float(row.get("successes", 0) or 0) + weight
            elif episode.verdict == VERDICT_REFUTED:
                row["failures"] = float(row.get("failures", 0) or 0) + weight
            row["samples"] = float(row.get("samples", 0) or 0) + weight
            row["module_version"] = episode.module_version
            bandit[key] = row
            data["bandit"] = bandit
            data["version"] = STORE_VERSION
            data.setdefault("context_fingerprint", episode.context_fingerprint)
            data.setdefault("tenant_id", episode.tenant_id)
            self._save_json(path, data)

    def bandit_stats(self, module_path: str, context_fingerprint: str, *, tenant: str = "default") -> Dict[str, float]:
        path = self._target_path(context_fingerprint, tenant)
        data = self._load_json(path)
        bandit = data.get("bandit") if isinstance(data.get("bandit"), dict) else {}
        row = bandit.get(module_path) if isinstance(bandit.get(module_path), dict) else {}
        return {
            "successes": float(row.get("successes", 0) or 0),
            "failures": float(row.get("failures", 0) or 0),
            "samples": float(row.get("samples", 0) or 0),
        }

    def query_similar_episodes(
        self,
        kb: Mapping[str, Any],
        *,
        context_fingerprint: str = "",
        tenant: str = "default",
        limit: int = 4,
    ) -> List[Dict[str, Any]]:
        mission_rows = retrieve_mission_episodes(kb, context_fingerprint=context_fingerprint, limit=limit)
        if mission_rows:
            return mission_rows
        if not context_fingerprint:
            return []
        path = self._target_path(context_fingerprint, tenant)
        data = self._load_json(path)
        rows = [row for row in (data.get("episodes") or []) if isinstance(row, dict)]
        return rows[-max(1, int(limit or 1)):]

    def export_summary(self) -> Dict[str, Any]:
        root = self._ensure_root()
        global_data = self._load_json(self._global_path)
        pref_data = self._load_json(self._preferences_path)
        target_files = list(root.glob("target_*.json"))
        return sanitize_nested({
            "global_episodes": len(global_data.get("episodes") or []),
            "preferences": len(pref_data.get("preferences") or []),
            "target_stores": len(target_files),
            "root": str(root),
        })

    def utility_multiplier(self, module_path: str, kb: Mapping[str, Any], state: Any = None) -> float:
        from interfaces.command_system.builtin.agent.contextual_bandit import bandit_multiplier

        if not module_path:
            return 1.0
        if state is not None and not should_record_learning(state):
            # Reading bandit stats is allowed during eval; writing is blocked elsewhere.
            pass
        index = build_context_index(state or type("S", (), {"knowledge_base": kb, "target_info": {}, "host_profile": {}})(), kb)
        fingerprint = build_context_fingerprint(index)
        tenant = tenant_id(state) if state is not None else "default"
        return bandit_multiplier(self, module_path, fingerprint)
