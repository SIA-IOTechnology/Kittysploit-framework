#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent workflow orchestrator.

Phase behavior lives in the mixins under ``workflow/``. This class wires those
pieces and runs scan, then analyze, reason, exploit, and report.
"""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403
from interfaces.command_system.builtin.agent.workflow.http_surface import HttpSurfaceMixin
from interfaces.command_system.builtin.agent.workflow.runtime_gates import RuntimeGateMixin
from interfaces.command_system.builtin.agent.workflow.module_execution import ModuleExecutionMixin
from interfaces.command_system.builtin.agent.workflow.knowledge import KnowledgeMixin
from interfaces.command_system.builtin.agent.workflow.planning import PlanningMixin
from interfaces.command_system.builtin.agent.workflow.scan_phase import ScanPhaseMixin
from interfaces.command_system.builtin.agent.workflow.analyze_phase import AnalyzePhaseMixin
from interfaces.command_system.builtin.agent.workflow.reason_phase import ReasonPhaseMixin
from interfaces.command_system.builtin.agent.workflow.exploit_phase import ExploitPhaseMixin
from interfaces.command_system.builtin.agent.workflow.report_phase import ReportPhaseMixin


class AgentWorkflowCore(
    HttpSurfaceMixin,
    RuntimeGateMixin,
    ModuleExecutionMixin,
    KnowledgeMixin,
    PlanningMixin,
    ScanPhaseMixin,
    AnalyzePhaseMixin,
    ReasonPhaseMixin,
    ExploitPhaseMixin,
    ReportPhaseMixin,
):
    """Orchestrates autonomous scan, analyze, reason, exploit, and report."""

    def __init__(self, framework):
        self.framework = framework
        self._catalog = ModuleCatalogService(framework)
        self._target_resolver = TargetResolver()
        self._llm = LocalLLMService(api_key=os.environ.get("KITTYMCP_OLLAMA_API_KEY"))
        self._planner = PlanningService(self._llm)
        self._report = ReportService()
        self._http_intel = HttpRequestIntelligence(framework)
        self._http_intel._llm = self._llm
        self._post_intel = PostExploitIntelligence(framework)
        self._auth_ops = AuthContextOperations(self._normalize_relative_path)
        self._module_perf = ModulePerformanceMemory()
        self._module_health = ModuleHealthMemory()
        self._module_ctx = ModuleContextMemory()
        self._learning = LearningStore()
        self._lifecycle = RunLifecycle()
        self._module_runner = AgentModuleRunner(WorkflowModuleRunnerHooks(self))
        self._module_executor = AgentModuleExecutionService(framework)
        self._paths = None

    def _memory_path(self, filename: str) -> str:
        if self._paths is not None:
            self._paths.ensure()
            return str(self._paths.memory_dir / filename)
        return os.path.expanduser(f"~/.kittysploit/agent/default/memory/{filename}")

    def _record_agent_error(
        self,
        state: AgentState,
        component: str,
        exc: Any,
        *,
        fatal: bool = False,
        phase: str = "",
    ) -> None:
        self._lifecycle.record_error(
            state,
            component,
            exc,
            fatal=fatal,
            phase=phase,
            append_timeline=self._append_timeline_event,
        )

    def _checkpoint_state(self, state: AgentState, phase: str) -> None:
        self._lifecycle.checkpoint_state(state, phase)
        from core.engagement.graph import project_agent_state

        project_agent_state(state, phase)

    def _phase_stop_reason(self, state: AgentState, phase: str) -> Optional[str]:
        return self._lifecycle.phase_stop_reason(state, phase)

    def _run_agent_flow(self, state: AgentState) -> AgentState:
        from core.vault.agent_bridge import bind_agent_runtime

        bind_agent_runtime(self.framework, state)
        install_requests_budget_hook()
        store = getattr(state, "run_store", None)
        if store is not None:
            self._paths = store.paths
            self._report.set_paths(store.paths)
            self._module_perf.set_paths(store.paths)
            self._module_health.set_paths(store.paths)
            self._module_ctx.set_paths(store.paths)
            self._learning.set_paths(store.paths)
        with network_budget_context(getattr(state, "network_budget", None)), runtime_policy_context(
            getattr(state, "runtime_policy", None),
            getattr(state, "scope_guard", None),
        ):
            if HAS_LANGGRAPH and state.current_phase in {"", "init", "scan"}:
                return self._run_with_langgraph(state)
            if not HAS_LANGGRAPH:
                print_warning("LangGraph not installed, using built-in linear workflow.")
            return self._run_linear_fallback(state)

    def _run_with_langgraph(self, state: AgentState) -> AgentState:
        graph = StateGraph(dict)

        def _wrap(fn):
            def _inner(raw: Dict[str, Any]) -> Dict[str, Any]:
                st = agent_state_from_dict(raw)
                from core.vault.agent_bridge import bind_agent_runtime

                bind_agent_runtime(self.framework, st)
                phase = fn.__name__.replace("_node_", "")
                st.phase_started_at = time.monotonic()
                st.current_phase = phase
                self._emit_phase_operator_event(st, phase)
                if st.error and phase != "report":
                    return agent_state_to_dict(st)
                if phase != "report" and self._phase_stop_reason(st, phase):
                    return agent_state_to_dict(st)
                out = fn(st)
                self._checkpoint_state(out, phase)
                return agent_state_to_dict(out)

            return _inner

        graph.add_node("scan", _wrap(self._node_scan))
        graph.add_node("analyze", _wrap(self._node_analyze))
        graph.add_node("reason", _wrap(self._node_reason))
        graph.add_node("exploit", _wrap(self._node_exploit))
        graph.add_node("report", _wrap(self._node_report))
        graph.set_entry_point("scan")
        graph.add_edge("scan", "analyze")
        graph.add_edge("analyze", "reason")
        graph.add_edge("reason", "exploit")
        graph.add_conditional_edges(
            "exploit",
            self._route_after_exploit,
            {"reason": "reason", "report": "report"},
        )
        graph.add_edge("report", END)

        app = graph.compile()
        try:
            return agent_state_from_dict(
                app.invoke(agent_state_to_dict(state), {"recursion_limit": 12})
            )
        except Exception as exc:
            if "recursion limit" not in str(exc).lower():
                raise
            print_warning(
                "LangGraph recursion guard tripped; falling back to the built-in linear workflow."
            )
            state.current_phase = "scan"
            return self._run_linear_fallback(state)

    def _run_linear_fallback(self, state: AgentState) -> AgentState:
        phases = (
            ("scan", self._node_scan),
            ("analyze", self._node_analyze),
            ("reason", self._node_reason),
            ("exploit", self._node_exploit),
            ("report", self._node_report),
        )
        names = [name for name, _fn in phases]
        start = state.current_phase if state.current_phase in names else "scan"
        start_index = names.index(start)
        for phase, fn in phases[start_index:]:
            state.phase_started_at = time.monotonic()
            state.current_phase = phase
            self._emit_phase_operator_event(state, phase)
            if phase != "report" and self._phase_stop_reason(state, phase):
                continue
            try:
                state = fn(state)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self._record_agent_error(state, phase, exc, fatal=True, phase=phase)
                state.error = f"{phase}: {exc}"
            self._checkpoint_state(state, phase)
            if phase == "exploit" and state.replan_pending and state.replan_count < 1:
                if state.verbose:
                    print_info("Low-confidence exploit phase — replanning with remaining LLM budget.")
                state = self._node_reason(state)
                self._checkpoint_state(state, "reason")
                state = self._node_exploit(state)
                self._checkpoint_state(state, "exploit")
            if state.error and phase != "report":
                break
        if state.current_phase != "report":
            state = self._node_report(state)
            self._checkpoint_state(state, "report")
        return state

    def _should_replan_after_exploit(self, state: AgentState) -> bool:
        if state.dry_run or state.plan_only or state.no_exploit:
            return False
        if not state.llm_local:
            return False
        if state.replan_count >= 1:
            return False
        if llm_budget_remaining(state) <= 0:
            return False
        if state.new_sessions:
            return False
        confidence = float((state.execution_plan or {}).get("reasoning_confidence", 1.0) or 1.0)
        if confidence < 0.55:
            return True
        if state.decision_source == "heuristic" and int(getattr(state.metrics, "llm_fallback_count", 0) or 0) > 0:
            return True
        if state.vulnerable_results and not state.new_sessions and confidence < 0.7:
            actions = (state.execution_plan or {}).get("next_actions") or []
            if actions:
                return True
        return False

    def _route_after_exploit(self, raw: Dict[str, Any]) -> str:
        state = agent_state_from_dict(raw)
        if state.replan_pending and state.replan_count < 1:
            raw["replan_pending"] = False
            raw["replan_count"] = 1
            return "reason"
        return "report"
