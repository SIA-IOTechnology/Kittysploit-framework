#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Verify agent run artifacts against lab ground-truth manifests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from core.lab_orchestrator.manifest import LabGroundTruthManifest
from interfaces.command_system.builtin.agent.attack_chain_memory import OBS_CONFIRMED
from interfaces.command_system.builtin.agent.benchmark.metrics import (
    count_false_successes,
    count_outcome_verdicts_from_state,
    has_confirmed_evidence,
    load_state_from_run_store,
)
from interfaces.command_system.builtin.agent.evidence_gate import gate_live_finding
from interfaces.command_system.builtin.agent.run_store import AgentPathService, AgentRunStore

PRIVILEGE_ORDER = {
    "guest": 0,
    "user": 1,
    "admin": 2,
    "root": 3,
    "system": 3,
}


@dataclass
class AgentRunContext:
    run_id: str
    state: Dict[str, Any]
    events: List[Dict[str, Any]] = field(default_factory=list)
    report_path: Optional[Path] = None
    report_text: str = ""


def resolve_run_id(check: Mapping[str, Any], lab_state: Optional[Mapping[str, Any]] = None) -> str:
    token = str(check.get("run_id") or "").strip()
    if token in {"$state:last_agent_run_id", "@state"}:
        token = ""
    if not token and lab_state:
        token = str(lab_state.get("last_agent_run_id") or "").strip()
    return token


def load_agent_run_context(
    framework: Any,
    run_id: str,
    *,
    paths: Optional[AgentPathService] = None,
) -> AgentRunContext:
    run_id = str(run_id or "").strip()
    if not run_id:
        raise ValueError("Agent run id is required")

    store = AgentRunStore(paths or AgentPathService(framework), run_id)
    state, events = load_state_from_run_store(store)
    report_path: Optional[Path] = None
    report_text = ""
    raw_report = str(state.get("report_path") or "").strip()
    if raw_report:
        report_path = Path(raw_report).expanduser()
        if report_path.is_file():
            report_text = report_path.read_text(encoding="utf-8", errors="replace")

    return AgentRunContext(
        run_id=run_id,
        state=state,
        events=list(events or []),
        report_path=report_path,
        report_text=report_text,
    )


def _state_blob(state: Mapping[str, Any]) -> str:
    return json.dumps(state, default=str, sort_keys=True).lower()


def discovered_service_ids(
    state: Mapping[str, Any],
    manifest: LabGroundTruthManifest,
) -> Set[str]:
    discovered: Set[str] = set()
    blob = _state_blob(state)

    for service in manifest.required_services():
        if str(service.host_port) in blob:
            discovered.add(service.id)
        if service.id in blob:
            discovered.add(service.id)
        if service.protocol and f"{service.protocol}/{service.host_port}" in blob:
            discovered.add(service.id)

    kb = state.get("knowledge_base") if isinstance(state.get("knowledge_base"), dict) else {}
    chain = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    for row in chain.get("observations") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("status", "")).lower() != OBS_CONFIRMED:
            continue
        module_path = str(row.get("module_path", "")).lower()
        for service in manifest.required_services():
            if service.id in module_path:
                discovered.add(service.id)

    for row in state.get("results") or []:
        if not isinstance(row, dict):
            continue
        row_blob = json.dumps(row, default=str).lower()
        for service in manifest.required_services():
            if str(service.host_port) in row_blob or service.id in row_blob:
                discovered.add(service.id)

    return discovered


def infer_privilege_level(state: Mapping[str, Any]) -> str:
    host_profile = state.get("host_profile") if isinstance(state.get("host_profile"), dict) else {}
    kb = state.get("knowledge_base") if isinstance(state.get("knowledge_base"), dict) else {}
    for container in (host_profile, kb, state.get("post_exploit") or {}):
        if not isinstance(container, dict):
            continue
        for key in ("privilege_level", "privilege", "effective_privilege", "privilege_tier"):
            value = str(container.get(key) or "").strip().lower()
            if value in PRIVILEGE_ORDER:
                return value

    blob = _state_blob(state)
    if "nt authority\\system" in blob or "uid=0" in blob or "root@" in blob:
        return "system"
    if "administrator" in blob or "uid=0(root)" in blob:
        return "admin"
    return "user"


def privilege_at_least(actual: str, expected: str) -> bool:
    return PRIVILEGE_ORDER.get(actual, 0) >= PRIVILEGE_ORDER.get(expected, 0)


def verify_agent_run(check: Mapping[str, Any], ctx: AgentRunContext) -> Tuple[bool, str]:
    if not ctx.state:
        return False, f"No checkpoint state for run {ctx.run_id}"

    if check.get("require_report") and not ctx.report_path:
        return False, "Missing agent report_path"

    if check.get("require_report") and ctx.report_path and not ctx.report_path.is_file():
        return False, f"Report file not found: {ctx.report_path}"

    if check.get("require_no_error") and ctx.state.get("error"):
        return False, f"Agent error: {str(ctx.state.get('error'))[:180]}"

    if check.get("require_no_scope_violations"):
        metrics = ctx.state.get("metrics") if isinstance(ctx.state.get("metrics"), dict) else {}
        blocks = int(metrics.get("scope_blocks", 0) or 0)
        if blocks > 0:
            return False, f"Scope violations detected: {blocks}"

    min_phases = check.get("min_phases_completed")
    if min_phases:
        completed = ctx.state.get("completed_phases") or []
        if len(completed) < int(min_phases):
            return False, f"Expected >= {min_phases} completed phases, got {len(completed)}"

    if check.get("require_timeline") and not ctx.events:
        return False, "No timeline events recorded for run"

    return True, f"Agent run {ctx.run_id} artifacts present"


def verify_service_coverage(
    check: Mapping[str, Any],
    ctx: AgentRunContext,
    manifest: LabGroundTruthManifest,
) -> Tuple[bool, str]:
    discovered = discovered_service_ids(ctx.state, manifest)
    required = manifest.required_services()
    if not required:
        return True, "No required services in manifest"

    ratio = len(discovered) / len(required)
    min_ratio = float(check.get("min_ratio", 0.9) or 0.9)
    missing = [svc.id for svc in required if svc.id not in discovered]
    detail = (
        f"Coverage {len(discovered)}/{len(required)} ({ratio:.0%}), "
        f"missing={missing or 'none'}"
    )
    return ratio >= min_ratio, detail


def verify_session(
    check: Mapping[str, Any],
    ctx: AgentRunContext,
    manifest: LabGroundTruthManifest,
) -> Tuple[bool, str]:
    sessions = ctx.state.get("new_sessions") or []
    if check.get("require_session") is not False and not sessions:
        return False, "No new_sessions recorded in agent state"

    if count_false_successes(ctx.state) > 0 and check.get("reject_false_success", True):
        return False, "Session claim without supporting report/evidence"

    contract = manifest.session or {}
    protocol = str(contract.get("protocol") or "").lower()
    if protocol:
        blob = _state_blob(ctx.state)
        if protocol not in blob and not sessions:
            return False, f"Expected session protocol '{protocol}' not observed"

    return True, f"Session verified ({len(sessions)} new session(s))"


def verify_privilege(
    check: Mapping[str, Any],
    ctx: AgentRunContext,
    manifest: LabGroundTruthManifest,
) -> Tuple[bool, str]:
    expected = str(check.get("min_level") or manifest.terminal_privilege or "user").lower()
    actual = infer_privilege_level(ctx.state)
    if privilege_at_least(actual, expected):
        return True, f"Privilege {actual} >= {expected}"
    return False, f"Privilege {actual} below required {expected}"


def verify_evidence(check: Mapping[str, Any], ctx: AgentRunContext) -> Tuple[bool, str]:
    min_confirmed = int(check.get("min_confirmed", 1) or 1)
    verdicts = count_outcome_verdicts_from_state(ctx.state)
    if verdicts.confirmed < min_confirmed and not has_confirmed_evidence(ctx.state):
        return False, f"Insufficient confirmed evidence ({verdicts.confirmed} observations)"

    if check.get("require_tool_provenance", True):
        blocked = 0
        for row in ctx.state.get("vulnerable_results") or []:
            if not isinstance(row, dict) or not row.get("vulnerable"):
                continue
            gate = gate_live_finding(row)
            if not gate.get("passed"):
                blocked += 1
        if blocked:
            return False, f"{blocked} vulnerable finding(s) failed evidence gate"

    if count_false_successes(ctx.state) > 0:
        return False, "False success detected (session/vuln without proof)"

    return True, f"Evidence verified (confirmed={verdicts.confirmed})"


def verify_report(check: Mapping[str, Any], ctx: AgentRunContext) -> Tuple[bool, str]:
    if not ctx.report_path or not ctx.report_path.is_file():
        return False, "Report file missing"

    text = ctx.report_text or ctx.report_path.read_text(encoding="utf-8", errors="replace")
    required_sections = [str(item) for item in (check.get("require_sections") or []) if item]
    missing = [section for section in required_sections if section.lower() not in text.lower()]
    if missing:
        return False, f"Report missing sections: {', '.join(missing)}"

    min_length = int(check.get("min_length", 200) or 200)
    if len(text) < min_length:
        return False, f"Report too short ({len(text)} chars)"

    return True, f"Report ok ({ctx.report_path})"


def verify_capability(
    check: Mapping[str, Any],
    ctx: AgentRunContext,
    manifest: LabGroundTruthManifest,
) -> Tuple[bool, str]:
    """Alias for service coverage with optional named capability requirement."""
    required_capability = str(check.get("capability") or "").strip()
    kb = ctx.state.get("knowledge_base") if isinstance(ctx.state.get("knowledge_base"), dict) else {}
    chain = kb.get("attack_chain_memory") if isinstance(kb.get("attack_chain_memory"), dict) else {}
    capabilities = {
        str(row.get("capability", "")).strip()
        for row in (chain.get("entries") or [])
        if isinstance(row, dict) and row.get("capability")
    }
    if required_capability:
        if required_capability in capabilities:
            return True, f"Capability '{required_capability}' unlocked"
        return False, f"Capability '{required_capability}' not found"

    passed, detail = verify_service_coverage(check, ctx, manifest)
    if passed:
        return True, f"Capability/service coverage ok — {detail}"
    return False, detail


def evaluate_agent_check(
    check: Mapping[str, Any],
    *,
    framework: Any,
    manifest: Optional[LabGroundTruthManifest],
    lab_state: Optional[Mapping[str, Any]] = None,
    ctx: Optional[AgentRunContext] = None,
) -> Tuple[bool, str]:
    check_type = str(check.get("type") or "").lower()
    if ctx is None:
        run_id = resolve_run_id(check, lab_state)
        if not run_id:
            return False, "Missing agent run_id (use --run-id or store last_agent_run_id in lab state)"
        try:
            ctx = load_agent_run_context(framework, run_id)
        except (OSError, ValueError) as exc:
            return False, str(exc)

    if check_type == "agent_run":
        return verify_agent_run(check, ctx)
    if check_type in {"service_coverage", "capability"}:
        if manifest is None:
            return False, "Manifest required for service coverage check"
        if check_type == "capability":
            return verify_capability(check, ctx, manifest)
        return verify_service_coverage(check, ctx, manifest)
    if check_type == "session":
        return verify_session(check, ctx, manifest or LabGroundTruthManifest(
            id="",
            version="1.0",
            image={},
            network={},
            credentials={},
        ))
    if check_type == "privilege":
        return verify_privilege(check, ctx, manifest or LabGroundTruthManifest(
            id="",
            version="1.0",
            image={},
            network={},
            credentials={},
        ))
    if check_type == "evidence":
        return verify_evidence(check, ctx)
    if check_type == "report":
        return verify_report(check, ctx)
    return False, f"Unsupported agent check type: {check_type or 'unknown'}"
