#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compound validation engine — deeper than Strix discovery→validate→report.

Pipeline per confirmed signal:
  1) Evidence gate + multi-refuter skeptic panel (heuristic or LLM)
  2) Parallel multi-step validation chain (retest → chain probe → browser/session PoC)
  3) Exploit queue promotion + automatic exploit-chain actions
  4) Power metrics (depth, parallelism) for campaign scoring
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.agent_run_journal import append_journal_event
from interfaces.command_system.builtin.agent.evidence_gate import gate_live_finding
from interfaces.command_system.builtin.agent.exploit_queue import (
    DECISION_EXPLOIT,
    classify_owasp_class,
    sync_exploit_queue_from_findings,
)
from interfaces.command_system.builtin.agent.metadata_chain_inference import infer_chain_metadata
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.refutation_panel import refute_finding_panel
from interfaces.command_system.builtin.agent.typed_models import AgentAction

COMPOUND_SCHEMA = "2.0"
POWER_KEY = "agent_power_metrics"


def _default_fanout() -> int:
    try:
        return max(1, min(8, int(os.environ.get("KITTYSPLOIT_VALIDATION_FANOUT", "4") or "4")))
    except (TypeError, ValueError):
        return 4


def validation_fanout_limit() -> int:
    return _default_fanout()


def bump_power_metrics(kb: MutableMapping[str, Any], **increments: int) -> None:
    store = kb.get(POWER_KEY)
    if not isinstance(store, dict):
        store = {
            "schema_version": COMPOUND_SCHEMA,
            "validation_depth": 0,
            "parallel_validations": 0,
            "skeptic_survived": 0,
            "skeptic_refuted": 0,
            "exploit_chains_spawned": 0,
            "strix_equivalent_score": 0,
        }
    for key, delta in increments.items():
        store[key] = int(store.get(key) or 0) + int(delta or 0)
    depth = int(store.get("validation_depth") or 0)
    parallel = int(store.get("parallel_validations") or 0)
    chains = int(store.get("exploit_chains_spawned") or 0)
    survived = int(store.get("skeptic_survived") or 0)
    store["strix_equivalent_score"] = depth * 3 + parallel * 5 + chains * 8 + survived * 2
    kb[POWER_KEY] = store


def finding_from_module_outcome(
    *,
    module_path: str,
    evidence: Sequence[Mapping[str, Any]],
    phase: str = "",
    message: str = "",
    vulnerable: bool = True,
) -> Dict[str, Any]:
    gate = gate_live_finding({
        "vulnerable": vulnerable,
        "evidence_records": list(evidence or []),
        "message": message,
        "severity": "high" if vulnerable else "info",
        "path": module_path,
        "module": module_path,
    })
    return sanitize_nested({
        "id": f"cmp_{module_path[-32:]}",
        "path": module_path,
        "module": module_path,
        "message": message or f"Module outcome: {module_path}",
        "vulnerable": vulnerable,
        "evidence_records": list(evidence or [])[:24],
        "evidence_gate": gate,
        "gate_blocked": not gate.get("passed"),
        "decision_class": DECISION_EXPLOIT if vulnerable and gate.get("passed") else "followup",
        "validation_status": "pending_compound",
        "phase": phase,
        "owasp_class": classify_owasp_class({"path": module_path, "message": message}),
    })


def run_skeptic_panel(
    finding: Mapping[str, Any],
    *,
    state: Any = None,
) -> Dict[str, Any]:
    use_llm = os.environ.get("KITTYSPLOIT_COMPOUND_LLM_SKEPTIC", "").strip().lower() in {
        "1", "true", "yes", "on",
    }
    llm = None
    endpoint = ""
    model = ""
    if use_llm and state is not None:
        llm = getattr(state, "local_llm", None)
        endpoint = str(getattr(state, "llm_endpoint", "") or "")
        model = str(getattr(state, "llm_model", "") or getattr(state, "llm_operator_model", "") or "")
    panel = refute_finding_panel(
        finding,
        refuters=3,
        llm_service=llm if use_llm else None,
        llm_endpoint=endpoint,
        llm_model=model,
        timeout=15,
    )
    return panel


def build_validation_chain(module_path: str) -> List[Dict[str, Any]]:
    """Multi-step chain (Strix++): retest, metadata follow-ups, browser/session PoC."""
    path = str(module_path or "").strip()
    if not path:
        return []
    steps: List[Dict[str, Any]] = []
    lowered = path.lower()

    retest = path
    if path.startswith("modules/"):
        retest = path.split("modules/", 1)[-1]
    if "scanner" in lowered or "auxiliary" in lowered or "browser" in lowered:
        steps.append({"tier": "retest", "path": retest, "reason": "same-module confirmation"})

    chain = infer_chain_metadata(retest)
    for follow in (chain.get("suggested_followups") or [])[:3]:
        token = str(follow or "").strip()
        if token and not any(s.get("path") == token for s in steps):
            steps.append({"tier": "chain_probe", "path": token, "reason": "metadata suggested_followup"})

    if any(tok in lowered for tok in ("xss", "dom", "browser", "csrf", "session")):
        for browser_mod in (
            "browser_auxiliary/misc/xss_dom_scanner",
            "browser_auxiliary/misc/generate_fingerprint",
        ):
            if not any(s.get("path") == browser_mod for s in steps):
                steps.append({"tier": "browser_poc", "path": browser_mod, "reason": "browser attack surface"})
                break

    if any(tok in lowered for tok in ("sqli", "rce", "shell", "exploit")):
        steps.append({
            "tier": "witness_capture",
            "path": "scanner/http/http_methods",
            "reason": "HTTP witness for exploit-class signal",
        })

    return steps[:6]


def register_compound_validation(
    kb: MutableMapping[str, Any],
    *,
    module_path: str,
    evidence: Sequence[Mapping[str, Any]],
    finding: Mapping[str, Any],
    panel: Mapping[str, Any],
    phase: str = "",
    state: Any = None,
) -> Optional[str]:
    from interfaces.command_system.builtin.agent.finding_validation_queue import enqueue_compound_validation

    steps = build_validation_chain(module_path)
    if not steps:
        return None
    return enqueue_compound_validation(
        kb,
        module_path=module_path,
        steps=steps,
        evidence=evidence,
        finding_id=str(finding.get("id") or ""),
        panel_verdict=str(panel.get("verdict") or ""),
        phase=phase,
        state=state,
    )


def process_confirmed_outcome(
    state: Any,
    *,
    module_path: str,
    evidence: Sequence[Mapping[str, Any]],
    phase: str = "",
    message: str = "",
) -> Dict[str, Any]:
    """Entry point after OBS_CONFIRMED in outcome_pipeline."""
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return {"skipped": True, "reason": "no_kb"}

    finding = finding_from_module_outcome(
        module_path=module_path,
        evidence=evidence,
        phase=phase,
        message=message,
    )
    if finding.get("gate_blocked"):
        bump_power_metrics(kb, skeptic_refuted=1)
        try:
            from interfaces.command_system.builtin.agent.compound_evidence_report import append_compound_witness

            append_compound_witness(
                kb,
                stage="skeptic",
                kind="evidence_gate_blocked",
                summary=f"Gate blocked {module_path}",
                payload={"gate": finding.get("evidence_gate")},
                state=state,
            )
        except Exception:
            pass
        return {"skipped": True, "reason": "evidence_gate", "gate": finding.get("evidence_gate")}

    panel = run_skeptic_panel(finding, state=state)
    verdict = str(panel.get("verdict") or "").upper()
    registry = list(kb.get("compound_validations") or [])
    record = sanitize_nested({
        "module_path": module_path,
        "finding_id": finding.get("id"),
        "panel_verdict": verdict,
        "phase": phase,
        "steps_planned": len(build_validation_chain(module_path)),
    })
    if verdict == "REFUTED":
        bump_power_metrics(kb, skeptic_refuted=1)
        record["status"] = "refuted"
        registry.append(record)
        kb["compound_validations"] = registry[-64:]
        try:
            from interfaces.command_system.builtin.agent.compound_evidence_report import append_compound_witness

            append_compound_witness(
                kb,
                stage="skeptic",
                kind="panel_refuted",
                summary=f"Skeptic refuted {module_path}",
                payload={"panel_verdict": verdict},
                state=state,
            )
        except Exception:
            pass
        append_journal_event(
            state,
            kind="compound_skeptic_refuted",
            summary=f"Skeptic refuted {module_path}",
            payload={"panel": verdict},
        )
        return {"skipped": True, "reason": "skeptic_refuted", "panel": panel}

    bump_power_metrics(kb, skeptic_survived=1, validation_depth=len(build_validation_chain(module_path)))

    cf = list(getattr(state, "contextual_findings", []) or [])
    finding["refutation_panel"] = panel
    finding["validation_status"] = "compound_queued"
    cf.append(finding)
    state.contextual_findings = cf[-120:]
    sync_exploit_queue_from_findings(kb, cf)

    vid = register_compound_validation(
        kb,
        module_path=module_path,
        evidence=evidence,
        finding=finding,
        panel=panel,
        phase=phase,
        state=state,
    )
    record["status"] = "queued"
    record["validation_id"] = vid
    registry.append(record)
    kb["compound_validations"] = registry[-64:]

    append_journal_event(
        state,
        kind="compound_validation_queued",
        summary=f"Compound chain ({record['steps_planned']} steps) for {module_path}",
        payload={"validation_id": vid, "owasp": finding.get("owasp_class")},
    )
    try:
        from interfaces.command_system.builtin.agent.compound_evidence_report import append_compound_witness

        append_compound_witness(
            kb,
            stage="skeptic",
            kind="panel_survived",
            summary=f"Skeptic cleared {module_path} → {record['steps_planned']} validation steps",
            payload={
                "validation_id": vid,
                "panel_verdict": verdict,
                "owasp_class": finding.get("owasp_class"),
                "steps_planned": record["steps_planned"],
            },
            state=state,
        )
    except Exception:
        pass
    return {"queued": True, "validation_id": vid, "steps": record["steps_planned"], "panel": verdict}


def spawn_exploit_chain_actions(state: Any, *, limit: int = 6) -> List[AgentAction]:
    """Drain gate-approved exploit queue into high-priority AgentActions."""
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return []
    from interfaces.command_system.builtin.agent.exploit_queue import (
        gate_queue_for_exploit,
        load_exploit_queue,
        queue_to_execution_actions,
    )

    approved = gate_queue_for_exploit(load_exploit_queue(kb))
    if not approved:
        return []
    raw_actions = queue_to_execution_actions(approved, limit=limit)
    try:
        from interfaces.command_system.builtin.agent.bug_bounty_mission import (
            filter_paths_for_bug_bounty,
            is_bug_bounty_mission,
        )

        if is_bug_bounty_mission(kb, mission_profile=str(getattr(getattr(state, "runtime_policy", None), "mission_profile", ""))):
            paths = filter_paths_for_bug_bounty(state, [str(r.get("path") or "") for r in raw_actions if r.get("path")])
            allowed = set(paths)
            raw_actions = [r for r in raw_actions if str(r.get("path") or "") in allowed]
    except Exception:
        pass
    actions: List[AgentAction] = []
    for row in raw_actions:
        if not isinstance(row, dict) or not row.get("path"):
            continue
        action_type = str(row.get("type") or "run_followup")
        if action_type == "run_exploit":
            action_type = "run_followup"
        actions.append(
            AgentAction(
                type=action_type,
                path=str(row.get("path")),
                priority=88 + int(row.get("priority") or 0),
                risk="active",
                reason=str(row.get("reason") or "compound_exploit_chain"),
                options={
                    "queue_item_id": row.get("queue_item_id"),
                    "compound_chain": True,
                    "owasp_class": row.get("owasp_class"),
                    "bug_bounty_poc": True,
                },
            )
        )
    if actions:
        bump_power_metrics(kb, exploit_chains_spawned=len(actions))
        append_journal_event(
            state,
            kind="exploit_chain_spawn",
            summary=f"Spawned {len(actions)} exploit-chain action(s)",
            payload={"paths": [a.path for a in actions[:8]]},
        )
        try:
            from interfaces.command_system.builtin.agent.compound_evidence_report import append_compound_witness

            append_compound_witness(
                kb,
                stage="exploit_chain",
                kind="spawn",
                summary=f"{len(actions)} exploit-chain action(s) queued",
                payload={"paths": [a.path for a in actions[:12]]},
                state=state,
            )
        except Exception:
            pass
    return actions


def power_status(kb: Mapping[str, Any]) -> Dict[str, Any]:
    metrics = kb.get(POWER_KEY) if isinstance(kb.get(POWER_KEY), dict) else {}
    validation = kb.get("finding_validation_queue") if isinstance(kb.get("finding_validation_queue"), dict) else {}
    exploit = kb.get("exploit_queue") if isinstance(kb.get("exploit_queue"), dict) else {}
    return sanitize_nested({
        "metrics": metrics,
        "validation_pending": len(validation.get("pending") or []),
        "validation_completed": len(validation.get("completed") or []),
        "exploit_queue_total": int((exploit.get("summary") or {}).get("total") or 0),
        "exploit_approved": int((exploit.get("summary") or {}).get("by_status", {}).get("approved") or 0),
        "compound_records": len(kb.get("compound_validations") or []),
        "compound_evidence": _compound_evidence_tail(kb),
    })


def _compound_evidence_tail(kb: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        from interfaces.command_system.builtin.agent.compound_evidence_report import build_compound_evidence_summary

        return build_compound_evidence_summary(kb)
    except Exception:
        return {}
