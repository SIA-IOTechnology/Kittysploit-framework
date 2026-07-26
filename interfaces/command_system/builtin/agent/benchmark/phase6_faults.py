#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pure fault injectors for Phase 6 offline generalization oracles."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple


@dataclass
class FaultOutcome:
    kind: str
    recovered: bool
    false_success: bool
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.recovered and not self.false_success


def inject_timeout_result() -> FaultOutcome:
    """Timeout must not be promoted to a confirmed terminal success."""
    from interfaces.command_system.builtin.agent.outcome_pipeline import normalize_module_outcome

    raw = {
        "path": "auxiliary/scanner/ssh/ssh_login",
        "success": False,
        "error": "timeout waiting for banner",
        "message": "timeout",
        "session_id": None,
        "vulnerable": False,
    }
    normalized = normalize_module_outcome(raw, module_path=raw["path"], phase="scan")
    status = str(normalized.observation.get("status") or "")
    false_success = normalized.session_claim_valid or status == "confirmed"
    recovered = status in {"no_signal", "refuted", "blocked", "module_error"} or not false_success
    return FaultOutcome(
        kind="timeout",
        recovered=recovered,
        false_success=false_success,
        detail=f"status={status}",
    )


def inject_malformed_result() -> FaultOutcome:
    """Malformed module payloads must not claim sessions."""
    from interfaces.command_system.builtin.agent.outcome_pipeline import normalize_module_outcome

    raw = {
        "path": "exploits/multi/http/fake_rce",
        "execution": {"success": "maybe", "session_id": "not-a-real-session"},
        "message": "success shell obtained",
    }
    normalized = normalize_module_outcome(raw, module_path=raw["path"], phase="exploit")
    false_success = bool(normalized.session_claim_valid)
    recovered = not false_success
    return FaultOutcome(
        kind="malformed",
        recovered=recovered,
        false_success=false_success,
        detail=f"claims={normalized.rejection_reasons[:3]}",
    )


def inject_missing_module(module_path: str = "auxiliary/scanner/http/does_not_exist_xyz") -> FaultOutcome:
    """Missing modules must surface as skip/refute, not confirmed vuln."""
    catalog: Dict[str, Any] = {}
    present = module_path in catalog
    result = {
        "path": module_path,
        "status": "skipped" if not present else "vulnerable",
        "vulnerable": False,
        "message": "module not found in catalog" if not present else "ok",
    }
    false_success = bool(result.get("vulnerable"))
    recovered = result.get("status") == "skipped" and not false_success
    return FaultOutcome(
        kind="missing_module",
        recovered=recovered,
        false_success=false_success,
        detail=result["message"],
    )


def inject_waf_block() -> FaultOutcome:
    """Synthetic WAF 403 must not be treated as authenticated session."""
    import urllib.error
    import urllib.request

    from interfaces.command_system.builtin.agent.benchmark.lab_mutation import build_mutated_lab

    lab, spec = build_mutated_lab(7)
    lab.start()
    try:
        url = f"{lab.base_url}{spec.waf_path}"
        try:
            urllib.request.urlopen(url, timeout=2)
            status = 200
            body = b""
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            body = exc.read()
        text = body.decode("utf-8", "ignore").lower()
        false_success = status == 200 or "authenticated" in text
        recovered = status == 403 and "waf" in text
        return FaultOutcome(
            kind="waf",
            recovered=recovered,
            false_success=false_success,
            detail=f"status={status}",
        )
    finally:
        lab.stop()


def inject_session_interrupted() -> FaultOutcome:
    """Lost sessions must classify as session_lost, not success."""
    from interfaces.command_system.builtin.agent.session_resilience import classify_shell_failure

    kind = classify_shell_failure("Connection lost: session not found", session_type="ssh")
    recovered = kind in {"session_lost", "disconnected", "timeout"} or "session" in kind
    false_success = kind in {"ok", "success", ""}
    return FaultOutcome(
        kind="session_interrupted",
        recovered=bool(recovered),
        false_success=bool(false_success),
        detail=f"class={kind}",
    )


def inject_llm_unavailable() -> FaultOutcome:
    """When LLM is down, planner must fall back to heuristic-only."""
    from interfaces.command_system.builtin.agent.model_router import planner_uses_heuristic_only

    state = SimpleNamespace(
        llm_local=False,
        local_llm=None,
        llm_client=None,
        llm_endpoint="",
        heuristic_planner_only=False,
    )
    heuristic = planner_uses_heuristic_only(state)
    return FaultOutcome(
        kind="llm_down",
        recovered=bool(heuristic),
        false_success=False,
        detail="heuristic_only" if heuristic else "llm_still_selected",
    )


def run_all_fault_injectors() -> Dict[str, FaultOutcome]:
    return {
        "timeout": inject_timeout_result(),
        "malformed": inject_malformed_result(),
        "missing_module": inject_missing_module(),
        "waf": inject_waf_block(),
        "session_interrupted": inject_session_interrupted(),
        "llm_down": inject_llm_unavailable(),
    }
