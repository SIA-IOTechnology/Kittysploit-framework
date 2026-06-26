#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal retest planning from prior findings or runs."""

from __future__ import annotations

import json
import os
from glob import glob
from typing import Any, Dict, List, Optional

from interfaces.command_system.builtin.agent.evidence import promote_evidence
from interfaces.command_system.builtin.agent.goal_planner import build_goal_plan
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.run_store import AgentPathService


class AgentRetestService:
    RETEST_STATUSES = ("fixed", "partial", "regressed", "unverified")

    def __init__(self, framework: Any, paths: Optional[AgentPathService] = None) -> None:
        self.framework = framework
        self.paths = paths or AgentPathService(framework)

    def build_retest_plan(self, finding_id: str) -> Dict[str, Any]:
        finding = self._find_finding(finding_id)
        if not finding:
            return {"error": f"finding not found: {finding_id}", "status": "unverified"}
        module = finding.get("module") or finding.get("path", "")
        plan = build_goal_plan("retest", request_budget=8)
        plan["next_actions"] = [{
            "type": "run_followup",
            "path": module,
            "priority": 1,
            "reason": f"retest finding {finding_id}",
        }]
        return sanitize_nested({
            "finding_id": finding_id,
            "module": module,
            "status": "unverified",
            "execution_plan": plan,
            "expected_proof": finding.get("evidence_state", "probable"),
        })

    def evaluate_retest_result(
        self,
        finding_id: str,
        *,
        vulnerable: bool,
        prior_state: str = "confirmed",
    ) -> Dict[str, Any]:
        if vulnerable:
            status = "regressed"
            new_state = promote_evidence(prior_state, retest_regressed=True)
        else:
            status = "fixed"
            new_state = promote_evidence(prior_state, retest_fixed=True)
        return {
            "finding_id": finding_id,
            "status": status,
            "evidence_state": new_state,
        }

    def _find_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        reports_dir = self.paths.reports_dir
        if not reports_dir.is_dir():
            return None
        for path in sorted(glob(str(reports_dir / "agent_report_*.json")), reverse=True):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (OSError, json.JSONDecodeError):
                continue
            for row in payload.get("contextual_findings") or []:
                if str(row.get("id", "")) == finding_id or str(row.get("path", "")) == finding_id:
                    return row
            for row in payload.get("vulnerabilities") or []:
                if str(row.get("id", "")) == finding_id or str(row.get("path", "")) == finding_id:
                    return row
        return None
