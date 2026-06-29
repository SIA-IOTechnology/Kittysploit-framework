#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Agent Markdown/JSON reports and historical false-positive heuristics."""

import os
from datetime import datetime
from typing import Any, Dict, List

from core.output_handler import print_error
from interfaces.command_system.builtin.agent.io_utils import (
    atomic_write_json,
    load_json_dict,
    update_json_dict,
)
from interfaces.command_system.builtin.agent.redaction import (
    SENSITIVE_KEY_MARKERS,
    is_sensitive_key,
    sanitize_nested,
)
from interfaces.command_system.builtin.agent.campaign_knowledge_graph import (
    summarize_attack_graph_for_report,
)
from interfaces.command_system.builtin.agent.run_store import AgentPathService, new_run_id


class ReportService:
    """Persist campaign reports and rolling per-path detection scores."""

    def __init__(self, paths: AgentPathService = None) -> None:
        self.paths = paths

    def set_paths(self, paths: AgentPathService) -> None:
        self.paths = paths

    def _memory_path(self, filename: str) -> str:
        if self.paths is not None:
            self.paths.ensure()
            return str(self.paths.memory_dir / filename)
        return os.path.join(
            os.path.expanduser("~/.kittysploit/agent/default/memory"),
            filename,
        )

    @staticmethod
    def _shorten(value: Any, limit: int = 180) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return text[: limit - 3].rstrip() + "..."

    @staticmethod
    def _finding_sort_key(row: Dict[str, Any]) -> Any:
        importance_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        decision_rank = {"exploit": 0, "followup": 1, "info": 2}
        return (
            importance_rank.get(str(row.get("importance", "low")).lower(), 9),
            decision_rank.get(str(row.get("decision_class", "info")).lower(), 9),
            -float(row.get("context_score", 0.0) or 0.0),
            str(row.get("path", "")),
        )

    def _build_report_summary(
        self,
        contextual_findings: List[Dict[str, Any]],
        llm_plan: Dict[str, Any],
        execution_plan: Dict[str, Any],
        knowledge_base: Dict[str, Any],
        decision_source: str = "heuristic",
    ) -> Dict[str, Any]:
        findings = [row for row in (contextual_findings or []) if isinstance(row, dict)]
        findings = sorted(findings, key=self._finding_sort_key)
        important_findings = findings[:8]
        decision_counts = {
            "exploit": len([f for f in findings if str(f.get("decision_class", "")).lower() == "exploit"]),
            "followup": len([f for f in findings if str(f.get("decision_class", "")).lower() == "followup"]),
            "info": len([f for f in findings if str(f.get("decision_class", "")).lower() == "info"]),
        }

        next_best_action = llm_plan.get("next_best_action", {})
        planned_actions = []
        for action in (execution_plan.get("next_actions", []) or []):
            if not isinstance(action, dict):
                continue
            action_type = str(action.get("type", "")).lower()
            if action_type not in ("run_followup", "run_exploit", "prioritize"):
                continue
            explanation = action.get("decision_explanation", {})
            if not isinstance(explanation, dict):
                explanation = {}
            planned_actions.append({
                "type": action_type,
                "path": str(action.get("path", "") or ""),
                "priority": action.get("priority"),
                "reason": str(action.get("reason") or explanation.get("reason") or ""),
                "decision_score": action.get("decision_score"),
                "confidence": action.get("confidence"),
                "decision_explanation": explanation,
            })
            if len(planned_actions) >= 6:
                break

        risk_signals = [str(x) for x in knowledge_base.get("risk_signals", []) or []]
        why_it_matters = []
        if decision_counts["exploit"]:
            why_it_matters.append("At least one finding is linked to a direct exploit path.")
        elif decision_counts["followup"]:
            why_it_matters.append("The strongest signals require validation or chained follow-up before exploitation.")
        elif findings:
            why_it_matters.append("Current findings are mostly informational and should not drive exploitation.")
        if knowledge_base.get("login_paths"):
            why_it_matters.append("Login surface was detected and may justify auth-first decisions.")
        if risk_signals:
            why_it_matters.append(f"Observed risk signals: {', '.join(risk_signals[:5])}.")
        request_intel = knowledge_base.get("request_intel", {}) if isinstance(knowledge_base, dict) else {}
        if isinstance(request_intel, dict) and int(request_intel.get("analyzed_flows", 0) or 0) > 0:
            why_it_matters.append(
                f"HTTP request intelligence analyzed {request_intel.get('analyzed_flows', 0)} captured flow(s)."
            )

        attack_graph = summarize_attack_graph_for_report(knowledge_base)

        return {
            "decision_counts": decision_counts,
            "important_findings": important_findings,
            "decision_summary": {
                "source": "LLM" if decision_source == "llm_local" else "Heuristic",
                "goal": execution_plan.get("campaign_goal"),
                "next_best_action": next_best_action if isinstance(next_best_action, dict) else {},
                "planned_actions": planned_actions,
                "rationale": llm_plan.get("rationale", ""),
                "reasoning_confidence": execution_plan.get("reasoning_confidence", 0.0),
            },
            "why_it_matters": why_it_matters,
            "attack_graph": attack_graph,
        }

    def load_history_scores(self) -> Dict[str, Any]:
        history_path = self._memory_path("history_scores.json")
        return load_json_dict(history_path)

    def update_history_scores(
        self,
        contextual_findings,
        new_sessions,
        session_provenance=None,
    ) -> None:
        history_path = self._memory_path("history_scores.json")
        provenance = session_provenance if isinstance(session_provenance, dict) else {}
        confirmed_paths = {
            str(path).lower()
            for session_id, path in provenance.items()
            if str(session_id) in {str(value) for value in (new_sessions or [])}
            and str(path).strip()
        }

        def _update(history):
            for finding in contextual_findings:
                path = str(finding.get("path", "")).lower()
                if not path:
                    continue
                related_paths = {path}
                exploit_path = str(finding.get("exploit_module", "") or "").lower()
                if exploit_path:
                    related_paths.add(exploit_path)
                related_paths.update(
                    str(value).lower()
                    for value in (finding.get("linked_modules") or [])
                    if str(value).strip()
                )
                confirmed = bool(related_paths.intersection(confirmed_paths))
                entry = history.get(path, {})
                entry["detections"] = int(entry.get("detections", 0)) + 1
                entry["last_seen"] = datetime.now().isoformat()
                entry["confirmed_hits"] = int(entry.get("confirmed_hits", 0)) + (1 if confirmed else 0)
                severity = str(finding.get("severity", "")).lower()
                likely_fp = (
                    not confirmed
                    and (
                        (not finding.get("exploit_module") and severity in ("low", "info"))
                        or finding.get("context_score", 0) < 1.2
                    )
                )
                entry["likely_false_positives"] = int(
                    entry.get("likely_false_positives", 0)
                ) + (1 if likely_fp else 0)
                history[path] = entry
            return history

        try:
            update_json_dict(history_path, _update)
        except Exception:
            return

    def _is_sensitive_key(self, key: Any) -> bool:
        return is_sensitive_key(key)

    def _redact_sensitive_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: "[redacted]" for k in value.keys()}
        if isinstance(value, list):
            return ["[redacted]" for _ in value]
        if isinstance(value, tuple):
            return ["[redacted]" for _ in value]
        return "[redacted]"

    def _sanitize_nested(self, value: Any, parent_key: str = "") -> Any:
        return sanitize_nested(value, parent_key)

    def sanitize_report_result(self, result):
        if not isinstance(result, dict):
            return result
        return self._sanitize_nested(dict(result))

    def sanitize_report_knowledge_base(self, knowledge_base):
        if not isinstance(knowledge_base, dict):
            return knowledge_base
        return self._sanitize_nested(dict(knowledge_base))

    def generate_report(
        self,
        raw_target,
        target_info,
        results,
        sql_findings,
        new_sessions,
        llm_plan,
        knowledge_base,
        execution_plan,
        contextual_findings=None,
        decision_timeline=None,
        *,
        run_id=None,
        workspace="default",
        metrics=None,
        campaign_stop_reason=None,
        network_budget=None,
        runtime_policy=None,
        decision_source="heuristic",
    ):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_id = str(run_id or new_run_id())
            if self.paths is not None:
                self.paths.ensure()
                reports_dir = str(self.paths.reports_dir)
            else:
                reports_dir = os.path.expanduser("~/.kittysploit/agent/default/reports")
            os.makedirs(reports_dir, exist_ok=True)

            base_name = f"agent_report_{timestamp}_{run_id[-10:]}"
            md_path = os.path.join(reports_dir, f"{base_name}.md")
            json_path = os.path.join(reports_dir, f"{base_name}.json")

            vulnerable_results = [r for r in results if r.get("vulnerable")]
            error_results = [r for r in results if r.get("status") == "error"]
            safe_knowledge_base = self.sanitize_report_knowledge_base(knowledge_base)
            safe_vulnerable_results = [self.sanitize_report_result(r) for r in vulnerable_results]
            safe_sql_findings = [self.sanitize_report_result(r) for r in sql_findings]
            safe_error_results = [self.sanitize_report_result(r) for r in error_results]
            safe_contextual_findings = [self.sanitize_report_result(r) for r in (contextual_findings or [])]
            safe_decision_timeline = [self.sanitize_report_result(r) for r in (decision_timeline or [])]
            safe_llm_plan = self._sanitize_nested(dict(llm_plan or {}))
            safe_execution_plan = self._sanitize_nested(dict(execution_plan or {}))
            safe_network_budget = self._sanitize_nested(dict(network_budget or {}))
            report_summary = self._build_report_summary(
                safe_contextual_findings,
                safe_llm_plan,
                safe_execution_plan,
                safe_knowledge_base,
                decision_source=str(decision_source or "heuristic"),
            )

            payload = {
                "schema_version": "1.0",
                "run_id": run_id,
                "workspace": workspace,
                "target": self._sanitize_nested(raw_target, "target_url"),
                "resolved_target": self._sanitize_nested(target_info),
                "generated_at": datetime.now().isoformat(),
                "campaign_stop_reason": campaign_stop_reason,
                "stats": {
                    "executed_modules": len(results),
                    "vulnerabilities": len(vulnerable_results),
                    "sql_injection_findings": len(sql_findings),
                    "errors": len(error_results),
                    "new_sessions": len(new_sessions),
                    "request_intel_flows": int(
                        (safe_knowledge_base.get("request_intel", {}) or {}).get("analyzed_flows", 0)
                        if isinstance(safe_knowledge_base.get("request_intel", {}), dict)
                        else 0
                    ),
                },
                "network_budget": safe_network_budget,
                "metrics": self._sanitize_nested(metrics or {}),
                "runtime_policy": self._sanitize_nested(runtime_policy or {}),
                "llm_plan": safe_llm_plan,
                "knowledge_base": safe_knowledge_base,
                "execution_plan": safe_execution_plan,
                "report_summary": report_summary,
                "decision_timeline": safe_decision_timeline,
                "new_sessions": new_sessions,
                "vulnerabilities": safe_vulnerable_results,
                "contextual_findings": safe_contextual_findings,
                "sql_findings": safe_sql_findings,
                "errors": safe_error_results,
            }

            atomic_write_json(json_path, payload)

            with open(md_path, "w", encoding="utf-8") as report_md:
                report_md.write("# KittySploit Agent Report\n\n")
                report_md.write(f"- Target: `{payload['target']}`\n")
                report_md.write(f"- Run ID: `{run_id}`\n")
                report_md.write(f"- Workspace: `{workspace}`\n")
                report_md.write(f"- Generated at: `{payload['generated_at']}`\n")
                report_md.write(f"- Executed modules: `{len(results)}`\n")
                report_md.write(f"- Vulnerabilities found: `{len(vulnerable_results)}`\n")
                report_md.write(f"- SQL injection findings: `{len(sql_findings)}`\n")
                report_md.write(f"- New sessions: `{len(new_sessions)}`\n")
                if safe_network_budget:
                    report_md.write("\n## Network Budget\n")
                    report_md.write(f"- Limit: `{safe_network_budget.get('limit', 0)}`\n")
                    report_md.write(f"- Used: `{safe_network_budget.get('used', 0)}`\n")
                    report_md.write(f"- Skipped: `{safe_network_budget.get('skipped', 0)}`\n")
                    if safe_network_budget.get("phase"):
                        report_md.write(f"- Last phase: `{safe_network_budget.get('phase')}`\n")
                    if safe_network_budget.get("last_action"):
                        report_md.write(
                            f"- Last action: {self._shorten(safe_network_budget.get('last_action'), 220)}\n"
                        )
                report_md.write("\n")

                attack_graph = report_summary.get("attack_graph") or {}
                if isinstance(attack_graph, dict) and int(attack_graph.get("nodes", 0) or 0) > 0:
                    report_md.write("## Attack Graph\n")
                    report_md.write(
                        f"- Nodes: `{attack_graph.get('nodes', 0)}` | "
                        f"Edges: `{attack_graph.get('edges', 0)}` | "
                        f"Last Δ: `{attack_graph.get('last_delta', 0)}`\n"
                    )
                    by_kind = attack_graph.get("nodes_by_kind") or {}
                    if isinstance(by_kind, dict) and by_kind:
                        kind_line = ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items()))
                        report_md.write(f"- By kind: {kind_line}\n")
                    nxt = attack_graph.get("next_action") if isinstance(attack_graph.get("next_action"), dict) else {}
                    if nxt.get("action"):
                        report_md.write(
                            f"- Next graph action: `{nxt.get('action')}` "
                            f"(confidence={float(nxt.get('confidence', 0.0) or 0.0):.2f})\n"
                        )
                    stale = attack_graph.get("stale_modules") or []
                    if stale:
                        report_md.write(f"- Stale (no graph growth): {', '.join(f'`{m}`' for m in stale[:6])}\n")
                    sample_nodes = attack_graph.get("sample_nodes") or []
                    if sample_nodes:
                        report_md.write("- Sample nodes:\n")
                        for row in sample_nodes[:8]:
                            if not isinstance(row, dict):
                                continue
                            report_md.write(
                                f"  - `{row.get('kind', '')}` {self._shorten(str(row.get('label', '')), 72)} "
                                f"(conf={float(row.get('confidence', 0.0) or 0.0):.2f})\n"
                            )
                    report_md.write("\n")

                report_md.write("## Knowledge Context\n")
                report_md.write(f"- Tech hints: `{len(safe_knowledge_base.get('tech_hints', []))}`\n")
                report_md.write(f"- Tech confidence signals: `{len(safe_knowledge_base.get('tech_confidence', {}))}`\n")
                report_md.write(f"- Specializations: `{len(safe_knowledge_base.get('specializations', []))}`\n")
                report_md.write(f"- Observed modules: `{len(safe_knowledge_base.get('observed_modules', []))}`\n")
                report_md.write(f"- Discovered endpoints: `{len(safe_knowledge_base.get('discovered_endpoints', []))}`\n")
                report_md.write(f"- Discovered params: `{len(safe_knowledge_base.get('discovered_params', []))}`\n")
                request_intel = (
                    safe_knowledge_base.get("request_intel", {})
                    if isinstance(safe_knowledge_base.get("request_intel", {}), dict)
                    else {}
                )
                if request_intel:
                    report_md.write(
                        f"- HTTP request intelligence: `{request_intel.get('analyzed_flows', 0)}` flow(s), "
                        f"`{len(request_intel.get('interesting_requests', []) or [])}` interesting request(s)\n"
                    )
                if safe_knowledge_base.get("tech_confidence"):
                    top_conf = sorted(
                        [(k, v) for k, v in safe_knowledge_base.get("tech_confidence", {}).items()],
                        key=lambda row: row[1],
                        reverse=True,
                    )[:5]
                    report_md.write(
                        "- Top confidence: "
                        + ", ".join([f"{name}={score:.2f}" for name, score in top_conf])
                        + "\n"
                    )
                risk_signals = safe_knowledge_base.get("risk_signals", [])
                if risk_signals:
                    report_md.write(f"- Risk signals: {', '.join(risk_signals)}\n")
                else:
                    report_md.write("- Risk signals: none\n")
                report_md.write("\n")

                report_md.write("## Decision Summary\n")
                decision_summary = report_summary.get("decision_summary", {})
                report_md.write(f"- Goal: {decision_summary.get('goal') or 'N/A'}\n")
                report_md.write(f"- Confidence: {decision_summary.get('reasoning_confidence', 0.0)}\n")
                next_best_action = decision_summary.get("next_best_action", {}) or {}
                if next_best_action.get("type"):
                    score = next_best_action.get("decision_score")
                    confidence = next_best_action.get("confidence")
                    suffix = ""
                    if score is not None or confidence is not None:
                        suffix = (
                            f" score={float(score or 0.0):.2f}"
                            f" confidence={float(confidence or 0.0):.2f}"
                        )
                    report_md.write(
                        f"- Next best action: `{next_best_action.get('type')}` "
                        f"`{next_best_action.get('path', '')}`{suffix}\n"
                    )
                    if next_best_action.get("reason"):
                        report_md.write(
                            f"- Why this action: {self._shorten(next_best_action.get('reason'), 220)}\n"
                        )
                else:
                    report_md.write("- Next best action: none\n")
                report_md.write(f"- Rationale: {self._shorten(safe_llm_plan.get('rationale', 'N/A'), 240)}\n")
                selected = safe_llm_plan.get("selected_paths", [])
                if selected:
                    report_md.write("- Prioritized scanner paths:\n")
                    for path in selected:
                        report_md.write(f"  - `{path}`\n")
                else:
                    report_md.write("- Prioritized scanner paths: None\n")
                report_md.write(
                    f"- Execution confidence: {safe_execution_plan.get('reasoning_confidence', 0.0)}\n"
                )
                report_md.write(
                    f"- Execution max requests next phase: {safe_execution_plan.get('max_requests_next_phase', 0)}\n"
                )
                planned_actions = decision_summary.get("planned_actions", []) or []
                if planned_actions:
                    report_md.write("- Planned actions:\n")
                    for row in planned_actions:
                        score = row.get("decision_score")
                        confidence = row.get("confidence")
                        suffix = ""
                        if score is not None or confidence is not None:
                            suffix = (
                                f" score={float(score or 0.0):.2f}"
                                f" confidence={float(confidence or 0.0):.2f}"
                            )
                        report_md.write(f"  - `{row.get('type')}` `{row.get('path', '')}`{suffix}\n")
                        reason = row.get("reason") or (row.get("decision_explanation", {}) or {}).get("reason")
                        if reason:
                            report_md.write(f"    reason: {self._shorten(reason, 220)}\n")
                        explanation = row.get("decision_explanation", {}) or {}
                        evidence = explanation.get("evidence", []) if isinstance(explanation, dict) else []
                        if evidence:
                            report_md.write(
                                f"    evidence: {self._shorten('; '.join([str(x) for x in evidence[:4]]), 260)}\n"
                            )
                        if isinstance(explanation, dict):
                            rejected = explanation.get("rejected_alternatives", []) or []
                            for alt in rejected[:2]:
                                if isinstance(alt, dict) and alt.get("path"):
                                    report_md.write(
                                        f"    not `{alt.get('path')}`: "
                                        f"{self._shorten(str(alt.get('reason', '')), 180)}\n"
                                    )
                            pivot = explanation.get("next_pivot")
                            if pivot:
                                report_md.write(f"    next pivot: `{pivot}`\n")
                            risk = explanation.get("risk", {}) if isinstance(explanation.get("risk"), dict) else {}
                            if risk.get("level"):
                                report_md.write(
                                    f"    risk: {risk.get('level')} "
                                    f"(cost={risk.get('cost', '?')})\n"
                                )
                report_md.write("\n")

                report_md.write("## Important Findings\n")
                important_findings = report_summary.get("important_findings", []) or []
                if important_findings:
                    for item in important_findings:
                        report_md.write(
                            f"- [{str(item.get('importance', 'low')).upper()}/"
                            f"{str(item.get('decision_class', 'info')).upper()}] "
                            f"`{item.get('path', 'unknown')}` "
                            f"(score={float(item.get('context_score', 0.0) or 0.0):.2f})\n"
                        )
                        report_md.write(f"  {self._shorten(item.get('message', 'No details'), 240)}\n")
                else:
                    report_md.write("- None\n")
                report_md.write("\n")

                report_md.write("## Why This Matters\n")
                why_it_matters = report_summary.get("why_it_matters", []) or []
                if why_it_matters:
                    for line in why_it_matters:
                        report_md.write(f"- {self._shorten(line, 240)}\n")
                else:
                    report_md.write("- No additional decision context.\n")
                report_md.write("\n")

                report_md.write("## Decision Timeline\n")
                if safe_decision_timeline:
                    for row in safe_decision_timeline:
                        if not isinstance(row, dict):
                            continue
                        phase = str(row.get("phase", "?"))
                        kind = str(row.get("kind", "phase"))
                        summary = self._shorten(row.get("summary", ""), 220)
                        report_md.write(f"- `{phase}` [{kind}]: {summary}\n")
                        extra = row.get("extra", {}) or {}
                        explanation = (
                            extra.get("decision_explanation")
                            if isinstance(extra, dict)
                            else {}
                        ) or {}
                        if isinstance(explanation, dict) and explanation:
                            rejected = explanation.get("rejected_alternatives", []) or []
                            for alt in rejected[:2]:
                                if isinstance(alt, dict) and alt.get("path"):
                                    report_md.write(
                                        f"  not `{alt.get('path')}`: "
                                        f"{self._shorten(str(alt.get('reason', '')), 160)}\n"
                                    )
                            if explanation.get("next_pivot"):
                                report_md.write(f"  next pivot: `{explanation.get('next_pivot')}`\n")
                            risk = explanation.get("risk", {}) if isinstance(explanation.get("risk"), dict) else {}
                            if risk.get("level"):
                                report_md.write(
                                    f"  risk: {risk.get('level')} (cost={risk.get('cost', '?')})\n"
                                )
                        modules = row.get("modules", []) or []
                        if modules:
                            report_md.write(
                                f"  modules: {', '.join([f'`{str(m)}`' for m in modules[:4]])}\n"
                            )
                        result_summary = row.get("result_summary", {}) or {}
                        if result_summary:
                            report_md.write(
                                "  results: "
                                f"total={result_summary.get('total_results', 0)}, "
                                f"vulnerable={result_summary.get('vulnerable', 0)}, "
                                f"actionable={result_summary.get('actionable', 0)}, "
                                f"errors={result_summary.get('errors', 0)}\n"
                            )
                else:
                    report_md.write("- None\n")

                report_md.write("## New Sessions\n")
                if new_sessions:
                    for session_id in new_sessions:
                        report_md.write(f"- `{session_id}`\n")
                else:
                    report_md.write("- None\n")

                report_md.write("\n## Vulnerabilities\n")
                if vulnerable_results:
                    for item in vulnerable_results:
                        report_md.write(
                            f"- `{item.get('path', 'unknown')}`: {item.get('message', 'No details')}\n"
                        )
                else:
                    report_md.write("- None\n")

                report_md.write("\n## Output Files\n")
                report_md.write(f"- JSON: `{json_path}`\n")

            return md_path
        except Exception as exc:
            print_error(f"Failed to generate report: {exc}")
            return None
