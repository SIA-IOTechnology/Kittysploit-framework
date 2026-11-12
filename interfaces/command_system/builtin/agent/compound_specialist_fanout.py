#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Parallel OWASP-class specialist fan-out during compound validation waves.

Runs alongside ``pop_validation_actions`` so skeptics + multi-step validation and
class-scoped specialists execute in the same campaign beat.
"""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.compound_evidence_report import append_compound_witness
from interfaces.command_system.builtin.agent.exploit_queue import classify_owasp_class
from interfaces.command_system.builtin.agent.owasp_mission import (
    OWASP_WEB_CLASSES,
    apply_owasp_web_parallel_to_kb,
    normalize_owasp_classes,
    risk_signals_for_classes,
    specialist_keys_for_classes,
)
from interfaces.command_system.builtin.agent.proposal_arbiter import arbitrate_proposals
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.typed_models import AgentAction

WAVE_SCHEMA = "1.0"
WAVE_KEY = "compound_specialist_wave"
DEFAULT_FAN_OUT = 5


def specialist_fanout_limit(kb: Optional[Mapping[str, Any]] = None) -> int:
    try:
        raw = os.environ.get("KITTYSPLOIT_COMPOUND_SPECIALIST_FANOUT", "")
        if raw.strip():
            return max(1, min(8, int(raw)))
    except (TypeError, ValueError):
        pass
    if isinstance(kb, Mapping):
        wave = kb.get(WAVE_KEY)
        if isinstance(wave, dict):
            try:
                return max(1, min(8, int(wave.get("fan_out") or DEFAULT_FAN_OUT)))
            except (TypeError, ValueError):
                pass
    return DEFAULT_FAN_OUT


def _wave_store(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    store = kb.get(WAVE_KEY)
    if not isinstance(store, dict):
        store = {
            "schema_version": WAVE_SCHEMA,
            "due": False,
            "classes": [],
            "fan_out": specialist_fanout_limit(kb),
            "specialists_dispatched": False,
        }
        kb[WAVE_KEY] = store
    store.setdefault("schema_version", WAVE_SCHEMA)
    return store


def register_class_for_wave(
    kb: MutableMapping[str, Any],
    *,
    module_path: str = "",
    owasp_class: str = "",
    state: Any = None,
) -> None:
    """Mark OWASP specialist fan-out due for this compound validation epoch."""
    oc = str(owasp_class or "").strip().lower()
    if not oc or oc == "other":
        oc = classify_owasp_class({"path": module_path, "module": module_path})
    wave = _wave_store(kb)
    classes = list(wave.get("classes") or [])
    if oc and oc != "other" and oc not in classes:
        classes.append(oc)
    wave["classes"] = normalize_owasp_classes(classes) if classes else list(OWASP_WEB_CLASSES[:3])
    wave["due"] = True
    wave["fan_out"] = specialist_fanout_limit(kb)
    kb[WAVE_KEY] = wave
    append_compound_witness(
        kb,
        stage="validation",
        kind="specialist_wave_scheduled",
        summary=f"OWASP fan-out scheduled for {wave['classes']}",
        payload={"module_path": module_path, "owasp_class": oc},
        state=state,
    )


def proposals_to_compound_actions(
    proposals: Sequence[Any],
    *,
    classes: Sequence[str],
    limit: int,
) -> List[AgentAction]:
    allowed = set(specialist_keys_for_classes(classes))
    filtered = [p for p in proposals if str(getattr(p, "specialist", "") or "") in allowed]
    ranked = arbitrate_proposals(filtered, limit=max(1, limit))
    actions: List[AgentAction] = []
    for proposal in ranked:
        base = proposal.action
        opts = dict(base.options or {})
        opts.update({
            "compound_specialist": True,
            "compound_owasp_classes": list(classes),
            "specialist": proposal.specialist,
            "proposal_confidence": float(proposal.confidence or 0.0),
        })
        actions.append(
            replace(
                base,
                priority=max(int(base.priority or 0), 82),
                reason=f"compound_owasp_fanout:{proposal.specialist}",
                options=opts,
            )
        )
    return actions


def run_compound_specialist_fanout(
    state: Any,
    observation: Mapping[str, Any],
    services: Any,
    *,
    max_actions: Optional[int] = None,
) -> List[AgentAction]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return []
    wave = kb.get(WAVE_KEY)
    if not isinstance(wave, dict) or not wave.get("due") or wave.get("specialists_dispatched"):
        return []

    classes = normalize_owasp_classes(wave.get("classes"))
    fan_out = max_actions if max_actions is not None else int(wave.get("fan_out") or specialist_fanout_limit(kb))
    poc_only = False
    try:
        from interfaces.command_system.builtin.agent.bug_bounty_mission import is_bug_bounty_mission

        poc_only = is_bug_bounty_mission(kb)
    except Exception:
        poc_only = False
    apply_owasp_web_parallel_to_kb(kb, classes=classes, fan_out=fan_out, exploit=not poc_only)

    signals = [str(s) for s in (kb.get("risk_signals") or [])]
    signal_set = {s.lower() for s in signals}
    for token in risk_signals_for_classes(classes):
        if token.lower() not in signal_set:
            signals.append(token)
            signal_set.add(token.lower())
    kb["risk_signals"] = signals

    modules = list(observation.get("catalog_modules") or [])
    if not modules and services is not None:
        catalog_svc = getattr(services, "module_catalog", None)
        discover = getattr(catalog_svc, "discover_campaign_modules", None)
        if callable(discover):
            try:
                modules = list(discover(expanded=False) or [])
            except Exception:
                modules = []

    from interfaces.command_system.builtin.agent.action_catalog import build_admissible_catalog
    from interfaces.command_system.builtin.agent.specialist_runner import run_specialists

    catalog = build_admissible_catalog(
        modules=modules,
        kb=kb,
        goal=getattr(state, "campaign_goal", ""),
        executed_actions=getattr(state, "executed_actions", []) or [],
        state=state,
        learning_store=getattr(services, "learning", None) if services is not None else None,
    )
    llm_available = bool(getattr(state, "local_llm", None))
    proposals, records = run_specialists(
        "parallel",
        state,
        observation,
        catalog,
        llm_available=llm_available,
    )
    actions = proposals_to_compound_actions(proposals, classes=classes, limit=fan_out)

    wave["specialists_dispatched"] = True
    wave["due"] = False
    wave["proposal_paths"] = [str(a.path or "") for a in actions if a.path][:16]
    wave["specialist_keys"] = specialist_keys_for_classes(classes)
    wave["record_count"] = len(records)
    kb[WAVE_KEY] = wave

    append_compound_witness(
        kb,
        stage="specialist_fanout",
        kind="parallel_complete",
        summary=f"{len(actions)} action(s) from {len(records)} specialist run(s)",
        payload=sanitize_nested({
            "classes": classes,
            "specialists": [getattr(r, "specialist", "") for r in records[:fan_out]],
            "paths": wave["proposal_paths"],
        }),
        state=state,
    )
    try:
        from interfaces.command_system.builtin.agent.compound_validation_engine import bump_power_metrics

        bump_power_metrics(kb, parallel_validations=max(1, len(records)))
    except Exception:
        pass
    return actions


def maybe_run_compound_specialist_fanout(
    state: Any,
    observation: Mapping[str, Any],
    services: Any,
    *,
    validation_wave_active: bool = False,
) -> List[AgentAction]:
    """Dispatch at most once per wave while compound validation is in flight."""
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return []
    wave = kb.get(WAVE_KEY)
    if not isinstance(wave, dict) or not wave.get("due") or wave.get("specialists_dispatched"):
        return []
    if not validation_wave_active:
        store = kb.get("finding_validation_queue")
        pending = (store.get("pending") or []) if isinstance(store, dict) else []
        validation_wave_active = any(
            isinstance(r, dict) and r.get("compound") for r in pending
        )
    if not validation_wave_active:
        return []
    return run_compound_specialist_fanout(state, observation, services)


__all__ = [
    "maybe_run_compound_specialist_fanout",
    "register_class_for_wave",
    "run_compound_specialist_fanout",
    "specialist_fanout_limit",
    "proposals_to_compound_actions",
]
