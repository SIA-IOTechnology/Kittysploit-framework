#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Agent Markdown/JSON reports and historical false-positive heuristics."""

import os
from datetime import datetime
from typing import Any, Dict, List

from core.output_handler import print_error
from interfaces.command_system.builtin.agent.io_utils import atomic_write_json, load_json_dict


SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "csrf",
)


class ReportService:
    """Persist campaign reports and rolling per-path detection scores."""

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
            planned_actions.append({
                "type": action_type,
                "path": str(action.get("path", "") or ""),
                "priority": action.get("priority"),
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

        return {
            "decision_counts": decision_counts,
            "important_findings": important_findings,
            "decision_summary": {
                "source": "LLM" if execution_plan.get("reasoning_confidence", 0.0) and llm_plan.get("rationale") else "Heuristic",
                "goal": execution_plan.get("campaign_goal"),
                "next_best_action": next_best_action if isinstance(next_best_action, dict) else {},
                "planned_actions": planned_actions,
                "rationale": llm_plan.get("rationale", ""),
                "reasoning_confidence": execution_plan.get("reasoning_confidence", 0.0),
            },
            "why_it_matters": why_it_matters,
        }

    def load_history_scores(self) -> Dict[str, Any]:
        history_path = os.path.join(os.getcwd(), "reports", "agent", "history_scores.json")
        return load_json_dict(history_path)

    def update_history_scores(self, contextual_findings, new_sessions) -> None:
        history_path = os.path.join(os.getcwd(), "reports", "agent", "history_scores.json")
        history = self.load_history_scores()
        had_shell = bool(new_sessions)

        for finding in contextual_findings:
            path = str(finding.get("path", "")).lower()
            if not path:
                continue
            entry = history.get(path, {})
            entry["detections"] = int(entry.get("detections", 0)) + 1
            entry["last_seen"] = datetime.now().isoformat()
            entry["confirmed_hits"] = int(entry.get("confirmed_hits", 0)) + (1 if had_shell else 0)

            likely_fp = False
            severity = str(finding.get("severity", "")).lower()
            if not had_shell and not finding.get("exploit_module") and severity in ("low", "info"):
                likely_fp = True
            if finding.get("context_score", 0) < 1.2 and not had_shell:
                likely_fp = True
            if likely_fp:
                entry["likely_false_positives"] = int(entry.get("likely_false_positives", 0)) + 1
            else:
                entry["likely_false_positives"] = int(entry.get("likely_false_positives", 0))

            history[path] = entry

        try:
            atomic_write_json(history_path, history)
        except Exception:
            pass

    def _is_sensitive_key(self, key: Any) -> bool:
        low = str(key).strip().lower()
        if not low:
            return False
        return any(marker in low for marker in SENSITIVE_KEY_MARKERS)

    def _redact_sensitive_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: "[redacted]" for k in value.keys()}
        if isinstance(value, list):
            return ["[redacted]" for _ in value]
        if isinstance(value, tuple):
            return ["[redacted]" for _ in value]
        return "[redacted]"

    def _sanitize_nested(self, value: Any, parent_key: str = "") -> Any:
        if self._is_sensitive_key(parent_key):
            return self._redact_sensitive_value(value)
        if isinstance(value, dict):
            return {
                key: self._sanitize_nested(item, str(key))
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._sanitize_nested(item, parent_key) for item in value]
        if isinstance(value, tuple):
            return [self._sanitize_nested(item, parent_key) for item in value]
        return value

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
    ):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            reports_dir = os.path.join(os.getcwd(), "reports", "agent")
            os.makedirs(reports_dir, exist_ok=True)

            base_name = f"agent_report_{timestamp}"
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
            report_summary = self._build_report_summary(
                safe_contextual_findings,
                dict(llm_plan or {}),
                dict(execution_plan or {}),
                safe_knowledge_base,
            )

            payload = {
                "target": raw_target,
                "resolved_target": target_info,
                "generated_at": datetime.now().isoformat(),
                "stats": {
                    "executed_modules": len(results),
                    "vulnerabilities": len(vulnerable_results),
                    "sql_injection_findings": len(sql_findings),
                    "errors": len(error_results),
                    "new_sessions": len(new_sessions),
                },
                "llm_plan": llm_plan,
                "knowledge_base": safe_knowledge_base,
                "execution_plan": execution_plan,
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
                report_md.write(f"- Target: `{raw_target}`\n")
                report_md.write(f"- Generated at: `{payload['generated_at']}`\n")
                report_md.write(f"- Executed modules: `{len(results)}`\n")
                report_md.write(f"- Vulnerabilities found: `{len(vulnerable_results)}`\n")
                report_md.write(f"- SQL injection findings: `{len(sql_findings)}`\n")
                report_md.write(f"- New sessions: `{len(new_sessions)}`\n\n")

                report_md.write("## Knowledge Context\n")
                report_md.write(f"- Tech hints: `{len(safe_knowledge_base.get('tech_hints', []))}`\n")
                report_md.write(f"- Tech confidence signals: `{len(safe_knowledge_base.get('tech_confidence', {}))}`\n")
                report_md.write(f"- Specializations: `{len(safe_knowledge_base.get('specializations', []))}`\n")
                report_md.write(f"- Observed modules: `{len(safe_knowledge_base.get('observed_modules', []))}`\n")
                report_md.write(f"- Discovered endpoints: `{len(safe_knowledge_base.get('discovered_endpoints', []))}`\n")
                report_md.write(f"- Discovered params: `{len(safe_knowledge_base.get('discovered_params', []))}`\n")
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
                    report_md.write(
                        f"- Next best action: `{next_best_action.get('type')}` "
                        f"`{next_best_action.get('path', '')}`\n"
                    )
                    if next_best_action.get("reason"):
                        report_md.write(
                            f"- Why this action: {self._shorten(next_best_action.get('reason'), 220)}\n"
                        )
                else:
                    report_md.write("- Next best action: none\n")
                report_md.write(f"- Rationale: {self._shorten(llm_plan.get('rationale', 'N/A'), 240)}\n")
                selected = llm_plan.get("selected_paths", [])
                if selected:
                    report_md.write("- Prioritized scanner paths:\n")
                    for path in selected:
                        report_md.write(f"  - `{path}`\n")
                else:
                    report_md.write("- Prioritized scanner paths: None\n")
                report_md.write(
                    f"- Execution confidence: {execution_plan.get('reasoning_confidence', 0.0)}\n"
                )
                report_md.write(
                    f"- Execution max requests next phase: {execution_plan.get('max_requests_next_phase', 0)}\n"
                )
                planned_actions = decision_summary.get("planned_actions", []) or []
                if planned_actions:
                    report_md.write("- Planned actions:\n")
                    for row in planned_actions:
                        report_md.write(f"  - `{row.get('type')}` `{row.get('path', '')}`\n")
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
                        summary = self._shorten(row.get("summary", ""), 220)
                        report_md.write(f"- `{phase}`: {summary}\n")
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
