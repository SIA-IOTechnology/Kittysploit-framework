#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Narrow facades over :class:`AgentWorkflowCore`.

Public methods mirror the former ``AgentCommand._*`` helpers without the leading
underscore so tests and callers can depend on stable, purpose-named entry points.
"""

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

    def run_agent_flow(self, state: AgentState) -> AgentState:
        """Run LangGraph workflow or linear fallback (see :meth:`AgentWorkflowCore._run_agent_flow`)."""
        return self.core._run_agent_flow(state)
