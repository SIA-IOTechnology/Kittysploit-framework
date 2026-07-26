#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Extract and aggregate North Star metrics from agent run artifacts."""

from __future__ import annotations

import statistics
from collections import Counter
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.attack_chain_memory import (
    OBS_BLOCKED,
    OBS_CONFIRMED,
    OBS_ERROR,
    OBS_NO_SIGNAL,
    OBS_REFUTED,
)
from interfaces.command_system.builtin.agent.benchmark.models import (
    BenchmarkRunResult,
    FailureCause,
    NorthStarMetrics,
    OutcomeVerdictCounts,
)
from interfaces.command_system.builtin.agent.benchmark.suites import BenchmarkSuite
from interfaces.command_system.builtin.agent.timeline import load_events_from_store

_OBS_TO_VERDICT = {
    OBS_ERROR: "module_error",
    OBS_NO_SIGNAL: "no_signal",
    OBS_REFUTED: "refuted",
    OBS_BLOCKED: "blocked",
    OBS_CONFIRMED: "confirmed",
}


def classify_observation_status(status: str) -> Optional[str]:
    token = str(status or "").strip().lower()
    return _OBS_TO_VERDICT.get(token)


def count_outcome_verdicts_from_state(state: Mapping[str, Any]) -> OutcomeVerdictCounts:
    counts = OutcomeVerdictCounts()
    kb = state.get("knowledge_base") if isinstance(state.get("knowledge_base"), dict) else {}
    chain = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    observations = chain.get("observations") if isinstance(chain.get("observations"), list) else []

    for row in observations:
        if not isinstance(row, dict):
            continue
        verdict = classify_observation_status(str(row.get("status", "")))
        if verdict:
            setattr(counts, verdict, getattr(counts, verdict) + 1)

    metrics = state.get("metrics") if isinstance(state.get("metrics"), dict) else {}
    policy_denied = int(metrics.get("scope_blocks", 0) or 0) + int(
        metrics.get("approvals_denied", 0) or 0
    )
    counts.policy_denied += policy_denied
    return counts


def count_repeated_actions_without_new_info(state: Mapping[str, Any]) -> int:
    executed = [
        str(path).strip().lower()
        for path in (state.get("executed_actions") or [])
        if str(path).strip()
    ]
    if not executed:
        return 0
    seen: set[str] = set()
    repeats = 0
    kb = state.get("knowledge_base") if isinstance(state.get("knowledge_base"), dict) else {}
    chain = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    observations = chain.get("observations") if isinstance(chain.get("observations"), list) else []
    obs_by_module = {
        str(row.get("module_path", "")).strip().lower(): row
        for row in observations
        if isinstance(row, dict) and row.get("module_path")
    }
    for path in executed:
        if path in seen:
            obs = obs_by_module.get(path)
            if obs and str(obs.get("status", "")).lower() in {OBS_NO_SIGNAL, OBS_REFUTED, OBS_BLOCKED}:
                repeats += 1
            elif not obs:
                repeats += 1
        seen.add(path)
    return repeats


def count_false_successes(state: Mapping[str, Any]) -> int:
    false_count = 0
    sessions = state.get("new_sessions") or []
    if sessions and not state.get("report_path"):
        false_count += 1
    for row in state.get("vulnerable_results") or []:
        if not isinstance(row, dict):
            continue
        if row.get("vulnerable") and not row.get("evidence_records") and not row.get("message"):
            false_count += 1
    return false_count


def count_module_error_recovery(state: Mapping[str, Any]) -> Tuple[int, int]:
    kb = state.get("knowledge_base") if isinstance(state.get("knowledge_base"), dict) else {}
    chain = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    observations = chain.get("observations") if isinstance(chain.get("observations"), list) else []
    errors = 0
    recovered = 0
    errored_modules: set[str] = set()
    for row in observations:
        if not isinstance(row, dict):
            continue
        module_path = str(row.get("module_path", "")).strip().lower()
        status = str(row.get("status", "")).lower()
        if status == OBS_ERROR:
            errors += 1
            errored_modules.add(module_path)
        elif status == OBS_CONFIRMED and module_path not in errored_modules:
            continue
        elif status == OBS_CONFIRMED and errored_modules:
            recovered += 1
            errored_modules.discard(module_path)
    return recovered, errors


def count_human_interventions(state: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> int:
    metrics = state.get("metrics") if isinstance(state.get("metrics"), dict) else {}
    approvals = int(metrics.get("approvals_requested", 0) or 0)
    interactive = sum(
        1
        for row in events
        if str(row.get("kind", "")).lower() == "approval"
        and str((row.get("data") or {}).get("mode", "")).lower() == "interactive"
    )
    return approvals + interactive


def has_confirmed_evidence(state: Mapping[str, Any]) -> bool:
    kb = state.get("knowledge_base") if isinstance(state.get("knowledge_base"), dict) else {}
    chain = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    observations = chain.get("observations") if isinstance(chain.get("observations"), list) else []
    if any(str(row.get("status", "")).lower() == OBS_CONFIRMED for row in observations if isinstance(row, dict)):
        return True
    for row in state.get("vulnerable_results") or []:
        if not isinstance(row, dict) or not row.get("vulnerable"):
            continue
        if row.get("evidence_records"):
            return True
        if str(row.get("evidence_state") or "").lower() in {"confirmed", "exploitable"}:
            return True
    return False


def infer_failure_transition(state: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> Optional[str]:
    stop_reason = str(state.get("campaign_stop_reason") or "").strip()
    if stop_reason:
        return f"stop:{stop_reason}"
    phase = str(state.get("current_phase") or "").strip()
    if phase:
        return f"phase:{phase}"
    for row in reversed(list(events)):
        if str(row.get("kind", "")).lower() == "stop":
            summary = str(row.get("summary") or "").strip()
            if summary:
                return f"timeline:{summary[:120]}"
    error_events = state.get("error_events") or []
    if error_events and isinstance(error_events[-1], dict):
        component = str(error_events[-1].get("component") or "error")
        return f"error:{component}"
    return None


def infer_completed_phases(
    state: Mapping[str, Any],
    events: Optional[Sequence[Mapping[str, Any]]] = None,
) -> List[str]:
    explicit = state.get("completed_phases") or []
    if explicit:
        return [str(phase) for phase in explicit if str(phase).strip()]

    seen: set[str] = set()
    phases: List[str] = []
    for row in list(state.get("decision_timeline") or []) + list(events or []):
        if not isinstance(row, dict):
            continue
        phase = str(row.get("phase") or "").strip().lower()
        if phase and phase not in seen:
            seen.add(phase)
            phases.append(phase)

    current = str(state.get("current_phase") or "").strip().lower()
    if current and current not in seen:
        phases.append(current)
    return phases


def score_run_against_suite(
    state: Mapping[str, Any],
    suite: BenchmarkSuite,
    *,
    events: Optional[Sequence[Mapping[str, Any]]] = None,
) -> bool:
    event_rows = list(events or [])
    criteria = suite.success_criteria
    if criteria.get("require_report") and not state.get("report_path"):
        return False
    if criteria.get("require_reachable") and state.get("target_reachable") is False:
        return False
    if criteria.get("require_no_error") and state.get("error"):
        return False
    if criteria.get("require_confirmed_evidence") and not has_confirmed_evidence(state):
        return False
    if criteria.get("require_session") and not (state.get("new_sessions") or []):
        return False
    min_confirmed = int(criteria.get("min_confirmed_observations", 0) or 0)
    verdicts = count_outcome_verdicts_from_state(state)
    if verdicts.confirmed < min_confirmed:
        return False
    min_phases = criteria.get("min_phases_completed")
    if min_phases:
        completed = infer_completed_phases(state, event_rows)
        if len(completed) < int(min_phases):
            return False
    if criteria.get("require_no_scope_violations"):
        metrics = state.get("metrics") if isinstance(state.get("metrics"), dict) else {}
        if int(metrics.get("scope_blocks", 0) or 0) > 0:
            return False
    if criteria.get("require_stop_kind"):
        expected = str(criteria["require_stop_kind"]).lower()
        if not any(str(row.get("kind", "")).lower() == expected for row in event_rows):
            return False
    return True


def extract_run_metrics(
    *,
    run_index: int,
    run_id: str,
    state: Mapping[str, Any],
    suite: BenchmarkSuite,
    seed: Optional[int] = None,
    duration_seconds: float = 0.0,
    events: Optional[Sequence[Mapping[str, Any]]] = None,
    error: Optional[str] = None,
) -> BenchmarkRunResult:
    event_rows = list(events or [])
    metrics = state.get("metrics") if isinstance(state.get("metrics"), dict) else {}
    recovered, module_errors = count_module_error_recovery(state)
    outcome_verdicts = count_outcome_verdicts_from_state(state)
    repeated = count_repeated_actions_without_new_info(state)
    false_successes = count_false_successes(state)
    scope_violations = int(metrics.get("scope_blocks", 0) or 0)
    mission_completed = bool(not error and score_run_against_suite(state, suite, events=event_rows))

    return BenchmarkRunResult(
        run_index=run_index,
        seed=seed,
        run_id=run_id,
        mission_completed=mission_completed,
        human_interventions=count_human_interventions(state, event_rows),
        duration_seconds=duration_seconds,
        stop_reason=str(state.get("campaign_stop_reason") or "") or None,
        report_path=str(state.get("report_path") or "") or None,
        outcome_verdicts=outcome_verdicts,
        repeated_actions_without_new_info=repeated,
        false_successes=false_successes,
        scope_violations=scope_violations,
        module_errors_recovered=recovered,
        module_errors_total=module_errors,
        evidence_confirmed=has_confirmed_evidence(state),
        session_obtained=bool(state.get("new_sessions")),
        failure_transition=None if mission_completed else infer_failure_transition(state, event_rows),
        error=error,
    )


def aggregate_north_star(runs: Sequence[BenchmarkRunResult]) -> NorthStarMetrics:
    if not runs:
        return NorthStarMetrics()

    completed = sum(1 for row in runs if row.mission_completed)
    total_actions = sum(
        sum(row.outcome_verdicts.to_dict().values()) for row in runs
    )
    repeated = sum(row.repeated_actions_without_new_info for row in runs)
    false_successes = sum(row.false_successes for row in runs)
    module_errors = sum(row.module_errors_total for row in runs)
    recovered = sum(row.module_errors_recovered for row in runs)
    scope_violations = sum(row.scope_violations for row in runs)
    interventions = [row.human_interventions for row in runs]
    outcomes = [row.mission_completed for row in runs]

    reproducibility = 0.0
    if len(runs) > 1:
        by_seed: Dict[Optional[int], List[bool]] = {}
        for row in runs:
            by_seed.setdefault(row.seed, []).append(row.mission_completed)
        stable_groups = sum(
            1 for values in by_seed.values() if len(set(values)) == 1
        )
        reproducibility = stable_groups / max(1, len(by_seed))

    return NorthStarMetrics(
        mission_completion_rate=completed / len(runs),
        human_interventions_median=float(statistics.median(interventions)),
        repeated_actions_without_new_info_rate=(repeated / total_actions) if total_actions else 0.0,
        false_success_rate=(false_successes / len(runs)) if runs else 0.0,
        recovery_after_module_error_rate=(recovered / module_errors) if module_errors else 1.0,
        out_of_scope_actions=scope_violations,
        reproducibility_rate=reproducibility if len(runs) > 1 else (1.0 if completed == len(runs) else 0.0),
    )


def aggregate_outcome_verdicts(runs: Sequence[BenchmarkRunResult]) -> OutcomeVerdictCounts:
    total = OutcomeVerdictCounts()
    for row in runs:
        total.add(row.outcome_verdicts)
    return total


def rank_failure_causes(runs: Sequence[BenchmarkRunResult]) -> List[FailureCause]:
    counter: Counter[str] = Counter()
    examples: Dict[str, Tuple[str, Optional[str]]] = {}
    for row in runs:
        if row.mission_completed:
            continue
        cause = row.failure_transition or row.stop_reason or row.error or "unknown"
        counter[cause] += 1
        if cause not in examples:
            examples[cause] = (row.run_id, row.failure_transition)
    ranked = counter.most_common(8)
    return [
        FailureCause(
            cause=cause,
            count=count,
            example_run_id=examples.get(cause, (None, None))[0],
            example_transition=examples.get(cause, (None, None))[1],
        )
        for cause, count in ranked
    ]


def load_state_from_run_store(store: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    checkpoint: Dict[str, Any] = {}
    try:
        checkpoint = store.load_checkpoint() or {}
    except Exception:
        checkpoint = {}
    state = checkpoint.get("state") if isinstance(checkpoint.get("state"), dict) else {}
    events = load_events_from_store(store)
    return state, events
