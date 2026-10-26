#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Apply planner intelligence defaults (hierarchical / adaptive / specialists) to a live run."""

from __future__ import annotations

from typing import Any

from interfaces.command_system.builtin.agent.adhoc_autonomy import adhoc_autonomy_enabled
from interfaces.command_system.builtin.agent.adaptive_loop import adaptive_loop_enabled
from interfaces.command_system.builtin.agent.hierarchical_planner import hierarchical_planner_enabled
from interfaces.command_system.builtin.agent.mission_orchestrator import domain_orchestrator_enabled
from interfaces.command_system.builtin.agent.performance_planner import turbo_mode_enabled
from interfaces.command_system.builtin.agent.session_pursuit import session_pursuit_active
from interfaces.command_system.builtin.agent.tool_micro_loop import micro_loop_enabled
from interfaces.command_system.builtin.agent.specialist_army import specialist_army_enabled
from interfaces.command_system.builtin.agent.specialist_llm import specialist_llm_enabled
from interfaces.command_system.builtin.agent.specialist_runner import specialist_execution_mode


def apply_intelligence_defaults(state: Any) -> dict[str, Any]:
    """
    Materialize effective planner flags onto ``state`` for checkpoints and telemetry.

    Returns a small summary dict (mode selections) for optional logging.
    """
    hier = hierarchical_planner_enabled(state)
    adaptive = adaptive_loop_enabled(state)
    mode = specialist_execution_mode(state)

    state.hierarchical_planner_enabled = hier
    state.adaptive_loop_enabled = adaptive
    state.specialist_parallel_enabled = mode == "parallel"
    state.specialist_sequential_enabled = mode == "sequential"

    domain_orch = domain_orchestrator_enabled(state)
    specialist_llm = specialist_llm_enabled(state)
    army = specialist_army_enabled(state)
    turbo = turbo_mode_enabled(state)
    micro = micro_loop_enabled(state)
    pursuit = session_pursuit_active(state)
    adhoc = adhoc_autonomy_enabled(state)

    state.specialist_army_enabled = army  # type: ignore[attr-defined]
    state.adhoc_autonomy_enabled = adhoc  # type: ignore[attr-defined]
    state.turbo_mode_enabled = turbo  # type: ignore[attr-defined]
    state.micro_loop_enabled = micro  # type: ignore[attr-defined]

    summary = {
        "hierarchical_planner": hier,
        "adaptive_loop": adaptive,
        "specialists": mode,
        "domain_orchestrator": domain_orch,
        "specialist_llm": specialist_llm,
        "specialist_army": army,
        "turbo_mode": turbo,
        "micro_loop": micro,
        "session_pursuit": pursuit,
        "adhoc_autonomy": adhoc,
    }
    try:
        kb = getattr(state, "knowledge_base", None)
        if isinstance(kb, dict):
            kb["planner_intelligence"] = dict(summary)
            if army:
                kb["specialist_army"] = True
    except Exception:
        pass
    return summary
