#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Session/post-exploit resilience: loss, non-interactive shells, arch mismatch, payload/listener failures."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.host_primitives import (
    Platform,
    command_for,
    infer_platform,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.session_broker import (
    NEUTRAL_FAILURE_MARKERS,
    SessionBroker,
    neutral_output_valid,
)

SCHEMA_VERSION = "1.0"

SESSION_LOST_MARKERS = NEUTRAL_FAILURE_MARKERS + (
    "broken pipe",
    "channel closed",
    "eof",
    "shell died",
)
NON_INTERACTIVE_MARKERS = (
    "cannot allocate pty",
    "not a tty",
    "stdin: is not a tty",
    "winrm non-interactive",
)
PAYLOAD_LISTENER_MARKERS = (
    "payload",
    "listener",
    "reverse_tcp",
    "reverse_shell",
    "bind_tcp",
    "multi/handler",
    "session_acquire",
)
LISTENER_FAILURE_MARKERS = (
    "listener timeout",
    "no connection received",
    "handler failed",
    "payload execution failed",
    "connection refused",
)


@dataclass
class ResilienceScenarioResult:
    name: str
    passed: bool
    failure_kind: str = ""
    detail: str = ""
    recovery: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "name": self.name,
            "passed": self.passed,
            "failure_kind": self.failure_kind or None,
            "detail": self.detail,
            "recovery": self.recovery or None,
        })


@dataclass
class SessionResilienceReport:
    schema_version: str = SCHEMA_VERSION
    scenarios: List[ResilienceScenarioResult] = field(default_factory=list)
    passed: int = 0
    failed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "schema_version": self.schema_version,
            "passed": self.passed,
            "failed": self.failed,
            "scenarios": [row.to_dict() for row in self.scenarios],
        })


def classify_shell_failure(output: str, *, session_type: str = "") -> str:
    text = str(output or "").strip().lower()
    if not text:
        return "empty_output"
    if any(marker in text for marker in SESSION_LOST_MARKERS):
        return "session_lost"
    if any(marker in text for marker in NON_INTERACTIVE_MARKERS):
        return "non_interactive_shell"
    if neutral_output_valid(output, session_type=session_type):
        return "ok"
    return "unknown_shell_failure"


def classify_payload_listener_outcome(
    module_path: str,
    raw: Mapping[str, Any],
) -> str:
    path = str(module_path or "").lower()
    if not any(marker in path for marker in PAYLOAD_LISTENER_MARKERS):
        return ""
    message = str(raw.get("error") or raw.get("message") or "").lower()
    blocked = bool(raw.get("blocked"))
    if blocked:
        return "payload_listener_blocked"
    if any(marker in message for marker in LISTENER_FAILURE_MARKERS):
        if "timeout" in message:
            return "listener_timeout"
        return "listener_failure"
    if raw.get("success") and not raw.get("session_id"):
        return "payload_no_session"
    if not raw.get("success") and not blocked:
        return "payload_failure"
    return ""


def alternate_platform(platform: Platform) -> Platform:
    if platform == "linux":
        return "windows"
    if platform == "windows":
        return "linux"
    return "unknown"


def architecture_recovery_command(
    *,
    primitive_id: str,
    failed_platform: Platform,
) -> Tuple[str, Platform]:
    fallback = alternate_platform(failed_platform)
    if fallback == "unknown":
        return command_for(primitive_id, "unknown"), "unknown"
    return command_for(primitive_id, fallback), fallback


def record_resilience_event(
    kb: MutableMapping[str, Any],
    *,
    kind: str,
    session_id: str = "",
    module_path: str = "",
    detail: str = "",
    recovery: str = "",
) -> None:
    store = kb.setdefault("session_resilience", {})
    if not isinstance(store, dict):
        store = {}
        kb["session_resilience"] = store
    events = list(store.get("events") or [])
    events.append(sanitize_nested({
        "ts": time.time(),
        "kind": kind,
        "session_id": session_id,
        "module_path": module_path,
        "detail": detail[:240],
        "recovery": recovery[:160],
    }))
    store["events"] = events[-24:]
    store["schema_version"] = SCHEMA_VERSION


def handle_session_loss(
    broker: SessionBroker,
    session_id: str,
    *,
    state: Any = None,
    reason: str = "session_lost",
) -> Dict[str, Any]:
    token = str(session_id or "").strip()
    broker.close(token)
    record = broker._records.get(token)
    if record is not None:
        record.status = "lost"
        record.verified = False
        record.verification_reason = reason
        broker._records[token] = record

    kb = getattr(state, "knowledge_base", None) if state is not None else None
    if isinstance(kb, dict):
        record_resilience_event(
            kb,
            kind="session_lost",
            session_id=token,
            detail=reason,
            recovery="close_session_and_replan",
        )
        verified = [sid for sid in (getattr(state, "verified_sessions", []) or []) if str(sid) != token]
        if state is not None:
            state.verified_sessions = verified
            state.replan_pending = True
        broker.sync_to_kb(kb, state=state)
        from interfaces.command_system.builtin.agent.plan_recalc import sync_plan_recalc

        sync_plan_recalc(kb, state=state)

    return sanitize_nested({
        "session_id": token,
        "status": "lost",
        "reason": reason,
        "recovery": "close_session_and_replan",
    })


def assess_non_interactive_session(broker: SessionBroker, session_id: str) -> Tuple[bool, str]:
    _session_obj, category = broker._resolve_session(session_id)
    if category == "browser":
        return False, "non_interactive_browser"
    if broker.supports_command_session(session_id):
        return True, "interactive"
    record = broker.register(session_id, category=category)
    session_type = str(record.session_type or "").lower()
    if session_type in {"browser", "http", "https"}:
        return False, "non_interactive_browser"
    if session_type in {"php", "webshell", "mysql", "mssql"}:
        return False, "non_interactive_service_shell"
    return False, "non_interactive_unknown"


def process_execution_resilience(
    state: Any,
    module_path: str,
    raw: Mapping[str, Any],
) -> Optional[str]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return None
    kind = classify_payload_listener_outcome(module_path, raw)
    if not kind:
        return None
    recovery = "fallback_heuristic_planner"
    if kind == "listener_timeout":
        recovery = "retry_with_bind_or_staged_payload"
    elif kind == "payload_listener_blocked":
        recovery = "policy_denied_no_retry"
    record_resilience_event(
        kb,
        kind=kind,
        module_path=module_path,
        detail=str(raw.get("error") or raw.get("message") or "")[:240],
        recovery=recovery,
    )
    if kind not in {"payload_listener_blocked"}:
        state.replan_pending = True
    return kind


def _scenario_session_loss(_framework: Any) -> ResilienceScenarioResult:
    class _Shell:
        def execute_command(self, session_id, command, framework=None, pty=False):
            return {"output": "connection lost"}

    class _Mgr:
        browser_sessions = {}

        def get_session(self, sid):
            from core.session import SessionData

            return SessionData(id=sid, host="lab", port=22, session_type="ssh", data={})

    fw = type("F", (), {"session_manager": _Mgr(), "shell_manager": _Shell()})()
    broker = SessionBroker(fw)
    state = type("S", (), {"knowledge_base": {}, "verified_sessions": ["sess-loss"], "replan_pending": False})()
    ok, _ = broker.verify_neutral("sess-loss")
    assert ok is False
    handle_session_loss(broker, "sess-loss", state=state, reason="connection lost")
    passed = (
        broker._records["sess-loss"].status == "lost"
        and "sess-loss" not in state.verified_sessions
        and state.replan_pending is True
    )
    return ResilienceScenarioResult(
        name="session_loss",
        passed=passed,
        failure_kind="session_lost",
        detail="heartbeat/verify marks session lost and triggers replan",
        recovery="close_session_and_replan",
    )


def _scenario_non_interactive_shell(_framework: Any) -> ResilienceScenarioResult:
    class _Mgr:
        browser_sessions = {"sess-br": object()}

        def get_browser_session(self, sid):
            return {"id": sid}

        def get_session(self, sid):
            return None

    fw = type("F", (), {"session_manager": _Mgr(), "shell_manager": None})()
    broker = SessionBroker(fw)
    interactive, reason = assess_non_interactive_session(broker, "sess-br")
    return ResilienceScenarioResult(
        name="non_interactive_shell",
        passed=interactive is False and reason == "non_interactive_browser",
        failure_kind="non_interactive_shell",
        detail=reason,
        recovery="skip_post_exploit_primitives",
    )


def _scenario_architecture_mismatch(framework: Any) -> ResilienceScenarioResult:
    cmd, platform = architecture_recovery_command(
        primitive_id="identity.current_user",
        failed_platform="linux",
    )
    passed = platform == "windows" and "whoami" in cmd.lower()
    return ResilienceScenarioResult(
        name="architecture_mismatch",
        passed=passed,
        failure_kind="architecture_mismatch",
        detail=f"fallback_platform={platform}",
        recovery="alternate_platform_primitive",
    )


def _scenario_payload_listener_failure(framework: Any) -> ResilienceScenarioResult:
    state = type("S", (), {"knowledge_base": {}, "replan_pending": False})()
    kind = process_execution_resilience(
        state,
        "exploits/linux/ssh/session_acquire",
        {"success": False, "error": "listener timeout waiting for connection", "blocked": False},
    )
    passed = kind == "listener_timeout" and state.replan_pending is True
    return ResilienceScenarioResult(
        name="payload_listener_failure",
        passed=passed,
        failure_kind=kind or "none",
        detail="listener timeout classified",
        recovery="retry_with_bind_or_staged_payload",
    )


def run_session_resilience_scenarios(framework: Any = None) -> SessionResilienceReport:
    runners = (
        _scenario_session_loss,
        _scenario_non_interactive_shell,
        _scenario_architecture_mismatch,
        _scenario_payload_listener_failure,
    )
    report = SessionResilienceReport()
    for runner in runners:
        result = runner(framework)
        report.scenarios.append(result)
        if result.passed:
            report.passed += 1
        else:
            report.failed += 1
    return report
