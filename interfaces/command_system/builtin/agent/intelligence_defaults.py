#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Apply planner intelligence defaults (hierarchical / adaptive / specialists) to a live run."""

from __future__ import annotations

from typing import Any

from interfaces.command_system.builtin.agent.adaptive_loop import adaptive_loop_enabled
from interfaces.command_system.builtin.agent.hierarchical_planner import hierarchical_planner_enabled
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

    summary = {
        "hierarchical_planner": hier,
        "adaptive_loop": adaptive,
        "specialists": mode,
    }
    try:
        kb = getattr(state, "knowledge_base", None)
        if isinstance(kb, dict):
            kb["planner_intelligence"] = dict(summary)
    except Exception:
        pass
    return summary
