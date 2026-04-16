#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Typed agent campaign state (replaces ad-hoc ``dict``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class AgentMetrics:
    deterministic_steps: int = 0
    llm_calls: int = 0
    llm_fallback_count: int = 0


def _default_execution_plan() -> Dict[str, Any]:
    return {
        "next_actions": [],
        "max_requests_next_phase": 0,
        "stop_conditions": [],
        "reasoning_confidence": 0.0,
        "skip_exploitation": False,
    }


def _default_llm_plan() -> Dict[str, Any]:
    return {
        "selected_paths": [],
        "rationale": "No LLM plan generated.",
        "next_best_action": None,
    }


def _default_sessions_before() -> Dict[str, Set[str]]:
    return {"standard": set(), "browser": set()}


@dataclass
class AgentState:
    raw_target: str
    target_info: Dict[str, Any]
    scanner: Any
    protocol: Optional[str] = None
    threads: int = 5
    verbose: bool = False
    no_exploit: bool = False
    llm_local: bool = False
    llm_model: str = "llama3.1:8b"
    llm_endpoint: str = "http://127.0.0.1:11434/api/chat"
    max_modules: int = 40
    recon_modules: int = 12
    results: List[Any] = field(default_factory=list)
    vulnerable_results: List[Any] = field(default_factory=list)
    contextual_findings: List[Any] = field(default_factory=list)
    sql_findings: List[Any] = field(default_factory=list)
    llm_plan: Dict[str, Any] = field(default_factory=_default_llm_plan)
    execution_plan: Dict[str, Any] = field(default_factory=_default_execution_plan)
    decision_source: str = "heuristic"
    knowledge_base: Dict[str, Any] = field(default_factory=dict)
    new_sessions: List[Any] = field(default_factory=list)
    sessions_before: Dict[str, Set[str]] = field(default_factory=_default_sessions_before)
    report_path: Optional[str] = None
    error: Optional[str] = None
    metrics: AgentMetrics = field(default_factory=AgentMetrics)
    history_scores: Dict[str, Any] = field(default_factory=dict)
    host_profile: Dict[str, Any] = field(default_factory=dict)
    campaign_stop_reason: Optional[str] = None
    scan_specializations: List[str] = field(default_factory=list)
    scan_tech_hints: List[str] = field(default_factory=list)
    scan_modules_executed: int = 0
    potential_findings: List[Any] = field(default_factory=list)
    campaign_goal: Optional[str] = None
    target_reachable: Optional[bool] = None
    reachability_reason: Optional[str] = None
    decision_timeline: List[Any] = field(default_factory=list)


def agent_state_to_dict(state: AgentState) -> Dict[str, Any]:
    """Flat dict for LangGraph ``StateGraph(dict).invoke`` (preserves live objects e.g. ``scanner``)."""
    m = state.metrics
    return {
        "raw_target": state.raw_target,
        "target_info": state.target_info,
        "scanner": state.scanner,
        "protocol": state.protocol,
        "threads": state.threads,
        "verbose": state.verbose,
        "no_exploit": state.no_exploit,
        "llm_local": state.llm_local,
        "llm_model": state.llm_model,
        "llm_endpoint": state.llm_endpoint,
        "max_modules": state.max_modules,
        "recon_modules": state.recon_modules,
        "results": state.results,
        "vulnerable_results": state.vulnerable_results,
        "contextual_findings": state.contextual_findings,
        "sql_findings": state.sql_findings,
        "llm_plan": state.llm_plan,
        "execution_plan": state.execution_plan,
        "decision_source": state.decision_source,
        "knowledge_base": state.knowledge_base,
        "new_sessions": state.new_sessions,
        "sessions_before": {
            "standard": set(state.sessions_before.get("standard", set())),
            "browser": set(state.sessions_before.get("browser", set())),
        },
        "report_path": state.report_path,
        "error": state.error,
        "metrics": {
            "deterministic_steps": m.deterministic_steps,
            "llm_calls": m.llm_calls,
            "llm_fallback_count": m.llm_fallback_count,
        },
        "history_scores": state.history_scores,
        "host_profile": state.host_profile,
        "campaign_stop_reason": state.campaign_stop_reason,
        "scan_specializations": state.scan_specializations,
        "scan_tech_hints": state.scan_tech_hints,
        "scan_modules_executed": state.scan_modules_executed,
        "potential_findings": state.potential_findings,
        "campaign_goal": state.campaign_goal,
        "target_reachable": state.target_reachable,
        "reachability_reason": state.reachability_reason,
        "decision_timeline": state.decision_timeline,
    }


def _as_set(val: Any) -> Set[str]:
    if val is None:
        return set()
    if isinstance(val, set):
        return set(val)
    if isinstance(val, (list, tuple)):
        return set(val)
    return set()


def agent_state_from_dict(d: Dict[str, Any]) -> AgentState:
    """Rebuild :class:`AgentState` from a LangGraph merged dict."""
    mm = d.get("metrics") or {}
    if isinstance(mm, AgentMetrics):
        metrics = mm
    elif isinstance(mm, dict):
        metrics = AgentMetrics(
            deterministic_steps=int(mm.get("deterministic_steps", 0)),
            llm_calls=int(mm.get("llm_calls", 0)),
            llm_fallback_count=int(mm.get("llm_fallback_count", 0)),
        )
    else:
        metrics = AgentMetrics()

    sb = d.get("sessions_before") or {}
    sessions_before = {
        "standard": _as_set(sb.get("standard")),
        "browser": _as_set(sb.get("browser")),
    }

    return AgentState(
        raw_target=str(d.get("raw_target", "")),
        target_info=dict(d.get("target_info") or {}),
        scanner=d.get("scanner"),
        protocol=d.get("protocol"),
        threads=int(d.get("threads", 5)),
        verbose=bool(d.get("verbose", False)),
        no_exploit=bool(d.get("no_exploit", False)),
        llm_local=bool(d.get("llm_local", False)),
        llm_model=str(d.get("llm_model", "llama3.1:8b")),
        llm_endpoint=str(d.get("llm_endpoint", "http://127.0.0.1:11434/api/chat")),
        max_modules=int(d.get("max_modules", 40)),
        recon_modules=int(d.get("recon_modules", 12)),
        results=list(d.get("results") or []),
        vulnerable_results=list(d.get("vulnerable_results") or []),
        contextual_findings=list(d.get("contextual_findings") or []),
        sql_findings=list(d.get("sql_findings") or []),
        llm_plan=dict(d.get("llm_plan") or _default_llm_plan()),
        execution_plan=dict(d.get("execution_plan") or _default_execution_plan()),
        decision_source=str(d.get("decision_source", "heuristic")),
        knowledge_base=dict(d.get("knowledge_base") or {}),
        new_sessions=list(d.get("new_sessions") or []),
        sessions_before=sessions_before,
        report_path=d.get("report_path"),
        error=d.get("error"),
        metrics=metrics,
        history_scores=dict(d.get("history_scores") or {}),
        host_profile=dict(d.get("host_profile") or {}),
        campaign_stop_reason=d.get("campaign_stop_reason"),
        scan_specializations=list(d.get("scan_specializations") or []),
        scan_tech_hints=list(d.get("scan_tech_hints") or []),
        scan_modules_executed=int(d.get("scan_modules_executed", 0)),
        potential_findings=list(d.get("potential_findings") or []),
        campaign_goal=d.get("campaign_goal"),
        target_reachable=d.get("target_reachable"),
        reachability_reason=d.get("reachability_reason"),
        decision_timeline=list(d.get("decision_timeline") or []),
    )
