#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyze phase: classify findings and hand off the exploit queue."""

from interfaces.command_system.builtin.agent.workflow.imports import *  # noqa: F403


class AnalyzePhaseMixin:
    """Analyze phase: classify findings and hand off the exploit queue."""

    def _node_analyze(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        if state.target_reachable is False and not self._has_proxy_request_intel(state):
            print_warning(f"Analysis skipped: {state.reachability_reason or 'target unreachable'}")
            return state
        vulnerable_results = state.vulnerable_results
        knowledge_base = state.knowledge_base
        sql_findings = []
        for item in vulnerable_results:
            text_blob = " ".join([
                str(item.get("module", "")),
                str(item.get("path", "")),
                str(item.get("message", "")),
            ]).lower()
            if (
                ("sql" in text_blob and "injection" in text_blob)
                or "sqli" in text_blob
                or "sql_injection" in text_blob
            ):
                sql_findings.append(item)
        state.sql_findings = sql_findings
        if sql_findings:
            signals = list(knowledge_base.get("risk_signals", []) or [])
            signal_set = {str(s).lower() for s in signals}
            if "sql_signal" not in signal_set:
                signals.append("sql_signal")
            if "sqli_confirmed" not in signal_set and any(
                item.get("vulnerable")
                or str(item.get("severity", "")).lower() in {"critical", "high", "medium"}
                for item in sql_findings
                if isinstance(item, dict)
            ):
                signals.append("sqli_confirmed")
            knowledge_base["risk_signals"] = signals
            sync_branches_from_kb_signals(knowledge_base)
            state.knowledge_base = knowledge_base
        state.contextual_findings = self._deduplicate_findings(
            self._build_contextual_findings(vulnerable_results, knowledge_base)
        )
        if getattr(state, "refute_panel", False):
            state.contextual_findings = self._apply_refutation_panel(state, state.contextual_findings)
        # Materialize typed exploit queue after evidence gating (analyze→exploit handoff).
        queue_payload = sync_exploit_queue_from_findings(knowledge_base, state.contextual_findings)
        if is_owasp_web_parallel_mission(
            knowledge_base,
            mission_profile=str(
                getattr(getattr(state, "runtime_policy", None), "mission_profile", "") or ""
            ),
        ):
            filtered = filter_queue_by_mission_classes(queue_payload.get("items") or [], knowledge_base)
            from interfaces.command_system.builtin.agent.exploit_queue import store_exploit_queue

            queue_payload = store_exploit_queue(knowledge_base, filtered)
        state.knowledge_base = knowledge_base
        knowledge_base["campaign_findings_snapshot"] = [
            {
                "path": item.get("path"),
                "message": item.get("message"),
                "module": item.get("module"),
                "context_hints": list(item.get("context_hints", []) or [])[:6],
                "evidence_state": item.get("evidence_state"),
                "proof_quality": item.get("proof_quality"),
            }
            for item in (state.contextual_findings or [])[:40]
            if isinstance(item, dict)
        ]
        invalidate_playbook_planner_cache(knowledge_base)
        state.potential_findings = self._deduplicate_findings(
            self._identify_potential_findings(vulnerable_results)
        )
        if state.verbose:
            print_info(
                "Context snapshot: "
                f"{len(knowledge_base.get('discovered_endpoints', []))} endpoints, "
                f"{len(knowledge_base.get('discovered_params', []))} params, "
                f"{len(knowledge_base.get('tech_hints', []))} tech hints, "
                f"{len(knowledge_base.get('login_paths', []))} login paths"
            )

        self._print_detection_summary(state)

        exploit_count = len([f for f in state.contextual_findings if f.get("decision_class") == "exploit"])
        followup_count = len([f for f in state.contextual_findings if f.get("decision_class") == "followup"])
        info_count = len([f for f in state.contextual_findings if f.get("decision_class") == "info"])
        queue_summary = (queue_payload or {}).get("summary") if isinstance(queue_payload, dict) else {}
        approved_queue = int((queue_summary or {}).get("by_status", {}).get("approved", 0) or 0)
        blocked_queue = int((queue_summary or {}).get("by_status", {}).get("blocked", 0) or 0)

        if sql_findings:
            print_success(f"High-priority detection: SQL injection ({len(sql_findings)})")
        elif exploit_count:
            print_success(f"Exploitable findings detected: {exploit_count}")
        elif followup_count:
            print_warning(
                f"No direct exploit path yet. Follow-up investigation required on {followup_count} finding(s)."
            )
        elif vulnerable_results:
            print_warning(
                f"Only informational findings detected ({info_count or len(vulnerable_results)}). "
                "No direct exploitation candidate."
            )
        else:
            print_warning("No obvious vulnerabilities found")
        if approved_queue or blocked_queue:
            print_info(
                f"Exploit queue handoff: approved={approved_queue}, blocked={blocked_queue} "
                f"(gate-blocked items will not be promoted)."
            )
        self._append_timeline_event(
            state,
            "analyze",
            (
                f"Analysis classified findings: exploit={exploit_count}, "
                f"followup={followup_count}, info={info_count}; "
                f"exploit_queue approved={approved_queue} blocked={blocked_queue}."
            ),
            kind="analysis",
            results=state.contextual_findings,
        )
        return state
