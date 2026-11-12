#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Light validation for PentAGI-inspired agent flow helpers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Tuple


def scenario_typed_memory_search() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.typed_campaign_memory import (
        search_typed_memory,
        store_typed_memory,
    )

    kb: dict = {}
    store_typed_memory(kb, doc_type="exploit_path", title="test", body="sqli confirmed")
    hits = search_typed_memory(kb, query="sqli", limit=3)
    ok = len(hits) == 1 and hits[0].get("doc_type") == "exploit_path"
    return ok, "typed_memory", 0, 0


def scenario_subtask_patch() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.plan_subtask_refiner import apply_subtask_patch

    kb: dict = {"agent_flow": {"subtasks": [{"id": "st_1", "title": "recon", "status": "planned"}]}}
    result = apply_subtask_patch(kb, [{"op": "add", "title": "validate finding"}])
    ok = "add:validate finding" in (result.get("applied") or [])
    return ok, "subtask_patch", 0, 0


def scenario_compound_chain() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.compound_validation_engine import (
        build_validation_chain,
        process_confirmed_outcome,
    )

    state = SimpleNamespace(
        knowledge_base={},
        contextual_findings=[],
        run_journal=[],
        decision_timeline=[],
    )
    steps = build_validation_chain("scanner/http/sqli_engine")
    ok = len(steps) >= 2
    if ok:
        result = process_confirmed_outcome(
            state,
            module_path="scanner/http/sqli_engine",
            evidence=[{"kind": "http", "summary": "error-based signal"}],
            phase="test",
            message="SQL error observed",
        )
        ok = bool(result.get("queued")) or result.get("skipped")
    return ok, "compound_chain", 0, 0


def scenario_flow_barrier() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.agent_flow_barrier import (
        flow_awaiting_operator,
        request_operator_ask,
        submit_operator_answer,
    )

    kb: dict = {}
    state = SimpleNamespace(campaign_stop_reason=None)
    request_operator_ask(kb, question="Continue?", state=state)
    ok = flow_awaiting_operator(kb) and submit_operator_answer(kb, "yes", state=state)
    ok = ok and not flow_awaiting_operator(kb)
    return ok, "flow_barrier", 0, 0


def scenario_compound_evidence_ledger() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.compound_evidence_report import (
        append_compound_witness,
        build_compound_evidence_summary,
        enrich_report_payload,
    )

    kb: dict = {}
    append_compound_witness(kb, stage="skeptic", kind="test", summary="panel ok")
    append_compound_witness(kb, stage="validation", kind="step", summary="retest confirmed")
    summary = build_compound_evidence_summary(kb)
    payload = enrich_report_payload({"run_id": "t"}, kb)
    ok = (
        int(summary.get("witness_count") or 0) == 2
        and "compound_evidence" in payload
        and int((payload.get("compound_evidence") or {}).get("summary", {}).get("witness_count") or 0) == 2
    )
    return ok, "compound_evidence", 0, 0


def scenario_bug_bounty_profile() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.bug_bounty_mission import (
        apply_bug_bounty_to_kb,
        is_bug_bounty_mission,
    )
    from interfaces.command_system.builtin.agent.bug_bounty_report import build_bug_bounty_submissions
    from interfaces.command_system.builtin.agent.mission_profiles import apply_mission_profile

    profile = apply_mission_profile("bug-bounty")
    kb: dict = {}
    apply_bug_bounty_to_kb(kb, classes=profile.get("owasp_classes"), fan_out=5)
    ok = bool(profile.get("bug_bounty_mission")) and is_bug_bounty_mission(kb)
    subs = build_bug_bounty_submissions(
        [
            {
                "path": "scanner/http/sqli_engine",
                "owasp_class": "injection",
                "decision_class": "exploit",
                "validation_status": "compound_queued",
                "message": "SQL error in parameter",
            }
        ],
        kb=kb,
        target="https://lab.local",
    )
    ok = ok and int(subs.get("count") or 0) >= 1
    return ok, "bug_bounty", 0, 0


def scenario_compound_specialist_wave() -> Tuple[bool, str, int, int]:
    from interfaces.command_system.builtin.agent.compound_specialist_fanout import (
        proposals_to_compound_actions,
        register_class_for_wave,
        specialist_fanout_limit,
    )
    from interfaces.command_system.builtin.agent.typed_models import AgentAction, SpecialistProposal

    kb: dict = {}
    register_class_for_wave(kb, module_path="scanner/http/sqli_engine")
    wave = kb.get("compound_specialist_wave") or {}
    prop = SpecialistProposal(
        specialist="sqli",
        action=AgentAction(type="run_followup", path="scanner/http/sqli_engine", priority=10),
        confidence=0.8,
    )
    actions = proposals_to_compound_actions([prop], classes=wave.get("classes") or ["injection"], limit=3)
    ok = bool(wave.get("due")) and len(actions) == 1 and actions[0].options.get("compound_specialist")
    ok = ok and specialist_fanout_limit() >= 1
    return ok, "compound_specialist_wave", 0, 0


def run_all() -> int:
    scenarios = [
        scenario_typed_memory_search,
        scenario_subtask_patch,
        scenario_compound_chain,
        scenario_flow_barrier,
        scenario_compound_evidence_ledger,
        scenario_compound_specialist_wave,
        scenario_bug_bounty_profile,
    ]
    failed = []
    for fn in scenarios:
        ok, name, *_ = fn()
        if not ok:
            failed.append(name)
        print(f"{'OK' if ok else 'FAIL'} {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run_all())
