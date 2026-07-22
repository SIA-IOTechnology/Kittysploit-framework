#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Narrow facades over :class:`AgentWorkflowCore`.

Public methods mirror the former ``AgentCommand._*`` helpers without the leading
underscore so tests and callers can depend on stable, purpose-named entry points.
"""

from __future__ import annotations

import time

from interfaces.command_system.builtin.agent.state import AgentState


class _CoreFacade:
    __slots__ = ("_core",)

    def __init__(self, core) -> None:
        object.__setattr__(self, "_core", core)

    def __getattr__(self, name: str):
        core = object.__getattribute__(self, "_core")
        private = "_" + name
        if hasattr(core, private):
            return getattr(core, private)
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")


class ScanPlanner(_CoreFacade):
    """Ultra fingerprinting, module selection, adaptive scan campaign."""


class ExploitPlanner(_CoreFacade):
    """Heuristic / LLM execution plans, follow-ups, exploit orchestration."""


class KnowledgeBaseService(_CoreFacade):
    """Host profiles, tech confidence, KB updates from scanner output, post-auth hints."""


class AuthContextService(_CoreFacade):
    """Credential extraction, session seeding, login-surface prioritization, post-auth actions."""


class AgentServices:
    """Bundles workflow core with standalone components for :class:`AgentCommand`."""

    __slots__ = (
        "core",
        "target_resolver",
        "module_catalog",
        "knowledge",
        "scan",
        "exploit",
        "auth",
        "report",
        "llm",
    )

    def __init__(self, framework) -> None:
        from interfaces.command_system.builtin.agent.workflow_core import AgentWorkflowCore

        self.core = AgentWorkflowCore(framework)
        self.target_resolver = self.core._target_resolver
        self.module_catalog = self.core._catalog
        self.knowledge = KnowledgeBaseService(self.core)
        self.scan = ScanPlanner(self.core)
        self.exploit = ExploitPlanner(self.core)
        self.auth = AuthContextService(self.core)
        self.report = self.core._report
        self.llm = self.core._llm

    def bootstrap_recon_for_adaptive(self, state: AgentState) -> AgentState:
        """Run scan/analyze once before the adaptive loop (LangGraph/linear parity)."""
        phase = str(state.current_phase or "init")
        if phase in {"reason", "act", "exploit", "report"}:
            if phase in {"reason", "exploit"}:
                state.current_phase = "act"
            return state

        sequence = (
            ("scan", self.core._node_scan),
            ("analyze", self.core._node_analyze),
        )
        names = [name for name, _fn in sequence]
        if phase == "analyze":
            sequence = sequence[1:]
        elif phase not in {"", "init", "scan"}:
            return state

        start_index = names.index(phase) if phase in names else 0
        for name, fn in sequence[start_index:]:
            state.phase_started_at = time.monotonic()
            state.current_phase = name
            self.core._emit_phase_operator_event(state, name)
            if state.error:
                return state
            stop = self.core._phase_stop_reason(state, name)
            if stop:
                state.campaign_stop_reason = stop
                return state
            state = fn(state)
            if state.error or state.campaign_stop_reason:
                return state
        state.current_phase = "act"
        return state

    def run_agent_flow(self, state: AgentState) -> AgentState:
        """Run adaptive loop or LangGraph/linear workflow (see :meth:`AgentWorkflowCore._run_agent_flow`)."""
        from interfaces.command_system.builtin.agent.adaptive_loop import (
            AdaptiveLoopEngine,
            adaptive_loop_enabled,
        )
        from interfaces.command_system.builtin.agent.egress_gateway import agent_egress_context
        from interfaces.command_system.builtin.agent.network_budget import (
            install_requests_budget_hook,
            network_budget_context,
        )
        from interfaces.command_system.builtin.agent.runtime_policy import runtime_policy_context

        install_requests_budget_hook()
        store = getattr(state, "run_store", None)
        if store is not None:
            self.core._paths = store.paths
            self.report.set_paths(store.paths)
            self.core._module_perf.set_paths(store.paths)
            self.core._module_health.set_paths(store.paths)
            self.core._module_ctx.set_paths(store.paths)
        if getattr(state, "module_health", None) is None:
            state.module_health = self.core._module_health

        with network_budget_context(getattr(state, "network_budget", None)), runtime_policy_context(
            getattr(state, "runtime_policy", None),
            getattr(state, "scope_guard", None),
        ), agent_egress_context(getattr(state, "cancellation_token", None)):
            if adaptive_loop_enabled(state):
                state = self.bootstrap_recon_for_adaptive(state)
                if state.error or state.campaign_stop_reason:
                    return state
                return AdaptiveLoopEngine(self).run(state)
            return self.core._run_agent_flow(state)
