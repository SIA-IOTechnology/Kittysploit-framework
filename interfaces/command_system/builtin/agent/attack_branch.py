#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parked attack branches for obtain-shell backtracking (light → pivot → deep)."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.agent_constants import (
    HTTP_SQLI_POST_MODULE,
    HTTP_SQLI_SCANNER_MODULE,
    HTTP_SQLI_SCANNER_MODULE_LEGACY,
)
from interfaces.command_system.builtin.agent.goal_planner import (
    is_shell_operator_goal,
    normalize_goal,
)

SCHEMA_VERSION = "1.0"
KB_KEY = "attack_branches"

STATUS_OPEN = "open"
STATUS_PARKED = "parked"
STATUS_EXHAUSTED = "exhausted"
DEPTH_LIGHT = "light"
DEPTH_DEEP = "deep"

SQLI_SCANNERS = {
    HTTP_SQLI_SCANNER_MODULE,
    HTTP_SQLI_SCANNER_MODULE_LEGACY,
    "auxiliary/scanner/http/sqli_engine",
}


@dataclass
class AttackBranch:
    branch_id: str
    family: str
    status: str = STATUS_OPEN
    depth: str = DEPTH_LIGHT
    entry_module: str = ""
    deep_module: str = ""
    target_path: str = ""
    primitives: Dict[str, Any] = field(default_factory=dict)
    attempts: int = 0
    parked_reason: str = ""
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _branch_id(family: str, target: str) -> str:
    raw = f"{family}:{target or 'unknown'}"
    return f"br_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def _branches(kb: MutableMapping[str, Any]) -> List[Dict[str, Any]]:
    rows = kb.get(KB_KEY)
    if not isinstance(rows, list):
        rows = []
        kb[KB_KEY] = rows
    return rows


def _find_branch(kb: Mapping[str, Any], branch_id: str) -> Optional[Dict[str, Any]]:
    for row in kb.get(KB_KEY) or []:
        if isinstance(row, dict) and str(row.get("branch_id") or "") == branch_id:
            return row
    return None


def action_type_for_module_path(path: str) -> str:
    low = str(path or "").strip().lower()
    if low.startswith("exploits/") or low.startswith("exploit/"):
        return "run_exploit"
    if low.startswith("post/"):
        return "run_post"
    return "run_followup"


def register_sqli_branch(
    kb: MutableMapping[str, Any],
    *,
    module_path: str,
    details: Optional[Mapping[str, Any]] = None,
    message: str = "",
) -> Optional[str]:
    """Register or refresh a SQLi branch after light confirmation."""
    details = details if isinstance(details, Mapping) else {}
    target = str(
        details.get("inj_path")
        or details.get("url")
        or details.get("endpoint")
        or ""
    ).strip()
    if not target and message:
        for token in message.split():
            if token.startswith("/") and ".php" in token.lower():
                target = token.split("?", 1)[0]
                break
    if not target:
        for row in details.get("sqli_findings") or []:
            if isinstance(row, dict):
                target = str(row.get("url") or row.get("path") or row.get("endpoint") or "")
                if target:
                    break
    bid = _branch_id("sqli", target or module_path)
    rows = _branches(kb)
    existing = _find_branch(kb, bid)
    primitives = {
        "inj_param": details.get("inj_param") or details.get("parameter"),
        "inj_path": target,
        "inj_method": details.get("inj_method") or details.get("method"),
        "technique": details.get("technique") or details.get("sqli_type"),
    }
    if existing:
        existing["entry_module"] = module_path or existing.get("entry_module") or ""
        existing["deep_module"] = HTTP_SQLI_POST_MODULE
        existing["target_path"] = target or existing.get("target_path") or ""
        existing["primitives"] = {**(existing.get("primitives") or {}), **{k: v for k, v in primitives.items() if v}}
        if existing.get("status") == STATUS_EXHAUSTED:
            existing["status"] = STATUS_PARKED
        return bid
    rows.append(
        AttackBranch(
            branch_id=bid,
            family="sqli",
            status=STATUS_OPEN,
            depth=DEPTH_LIGHT,
            entry_module=str(module_path or ""),
            deep_module=HTTP_SQLI_POST_MODULE,
            target_path=target,
            primitives=primitives,
        ).to_dict()
    )
    return bid


def park_branch(kb: MutableMapping[str, Any], branch_id: str, *, reason: str = "") -> None:
    row = _find_branch(kb, branch_id)
    if not row:
        return
    row["status"] = STATUS_PARKED
    row["parked_reason"] = str(reason or "")[:240]
    row["depth"] = DEPTH_LIGHT


def mark_branch_exhausted(kb: MutableMapping[str, Any], branch_id: str) -> None:
    row = _find_branch(kb, branch_id)
    if row:
        row["status"] = STATUS_EXHAUSTED


def sync_branches_from_results(
    kb: MutableMapping[str, Any],
    results: Sequence[Mapping[str, Any]],
) -> List[str]:
    """Update branch registry from module results (sqli confirmed, etc.)."""
    touched: List[str] = []
    if not isinstance(kb, dict):
        return touched
    for result in results or []:
        if not isinstance(result, dict):
            continue
        mod_path = str(result.get("path") or result.get("module") or "")
        details = result.get("details") if isinstance(result.get("details"), dict) else {}
        msg = str(result.get("message") or "")
        low = mod_path.lower()
        sqli_rows = details.get("sqli_findings") if isinstance(details.get("sqli_findings"), list) else []
        sqli_hit = bool(sqli_rows) or "sqli" in msg.lower() or "sql injection" in msg.lower()
        if sqli_hit or any(token in low for token in ("sql_injection", "sqli_engine", "sqli")):
            bid = register_sqli_branch(kb, module_path=mod_path, details=details, message=msg)
            if bid:
                touched.append(bid)
                row = _find_branch(kb, bid)
                if row and mod_path in SQLI_SCANNERS:
                    row["depth"] = DEPTH_LIGHT
                    row["status"] = STATUS_PARKED
                    row["parked_reason"] = "light_sqli_confirmed_pivot_for_shell"
        if mod_path == HTTP_SQLI_POST_MODULE and result.get("success"):
            for row in _branches(kb):
                if isinstance(row, dict) and row.get("family") == "sqli":
                    row["status"] = STATUS_EXHAUSTED
                    row["depth"] = DEPTH_DEEP
    return touched


def parked_sqli_branches(kb: Mapping[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for row in kb.get(KB_KEY) or []:
        if not isinstance(row, dict):
            continue
        if row.get("family") == "sqli" and row.get("status") == STATUS_PARKED:
            out.append(row)
    return out


def goal_allows_sqli_deep_resume(goal: str = "") -> bool:
    """True for obtain-shell or auto-escalated exploit goals chasing SQLi."""
    if is_shell_operator_goal(goal):
        return True
    normalized = normalize_goal(goal) if str(goal or "").strip() else ""
    raw = str(goal or "").strip().lower().replace("-", "_")
    return normalized == "exploit" or raw == "exploit"


def pick_resumed_deep_action(
    kb: Mapping[str, Any],
    *,
    operator_goal: str = "",
) -> Optional[Dict[str, Any]]:
    """Return a deep SQLi action for a parked branch (obtain-shell or exploit chase)."""
    if not goal_allows_sqli_deep_resume(operator_goal):
        return None
    for row in parked_sqli_branches(kb):
        deep = str(row.get("deep_module") or HTTP_SQLI_POST_MODULE)
        if not deep:
            continue
        target = str(row.get("target_path") or "")
        reason = (
            f"Resume parked SQLi branch for deep shell attempt"
            + (f" on {target}" if target else "")
        )
        return {
            "type": action_type_for_module_path(deep),
            "path": deep,
            "reason": reason,
            "branch_id": row.get("branch_id"),
            "resume_branch": True,
        }
    return None


def pick_light_sqli_probe(
    kb: Mapping[str, Any],
    *,
    discovered_endpoints: Optional[Sequence[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Suggest light SQLi scanner on an interesting endpoint not yet probed."""
    endpoints = list(discovered_endpoints or kb.get("discovered_endpoints") or [])
    observed = {str(x) for x in kb.get("observed_modules") or []}
    if HTTP_SQLI_SCANNER_MODULE_LEGACY in observed and HTTP_SQLI_SCANNER_MODULE in observed:
        return None
    scanner = HTTP_SQLI_SCANNER_MODULE_LEGACY
    if HTTP_SQLI_SCANNER_MODULE_LEGACY in observed:
        scanner = HTTP_SQLI_SCANNER_MODULE
    for ep in endpoints:
        low = str(ep).lower()
        if ".php" in low and any(token in low for token in ("payroll", "login", "admin", "user", "id")):
            return {
                "type": "run_followup",
                "path": scanner,
                "reason": f"Light SQLi probe on discovered endpoint {ep}",
                "options": {"scan_paths": ep},
            }
    signals = {str(s).lower() for s in kb.get("risk_signals") or []}
    if "sql_signal" in signals or "sqli_confirmed" in signals:
        return None
    for ep in endpoints:
        if str(ep).lower().endswith(".php"):
            return {
                "type": "run_followup",
                "path": scanner,
                "reason": f"Light SQLi probe on {ep}",
                "options": {"scan_paths": ep},
            }
    return None


def sync_branches_from_kb_signals(kb: MutableMapping[str, Any]) -> Optional[str]:
    """Ensure a parked SQLi branch exists when risk signals already confirmed SQLi."""
    if not isinstance(kb, dict):
        return None
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if "sqli_confirmed" not in signals and "sql_signal" not in signals:
        return None
    if parked_sqli_branches(kb):
        return str(parked_sqli_branches(kb)[0].get("branch_id") or "") or None
    target = ""
    sqli_rows = kb.get("sqli_findings") if isinstance(kb.get("sqli_findings"), list) else []
    for row in sqli_rows:
        if isinstance(row, dict):
            target = str(row.get("url") or row.get("path") or row.get("endpoint") or "")
            if target:
                break
    if not target:
        for ep in kb.get("discovered_endpoints", []) or []:
            low = str(ep).lower()
            if ".php" in low and any(token in low for token in ("payroll", "login", "user", "admin")):
                target = str(ep)
                break
    if not target:
        for ep in kb.get("discovered_endpoints", []) or []:
            if str(ep).lower().endswith(".php"):
                target = str(ep)
                break
    bid = register_sqli_branch(
        kb,
        module_path=HTTP_SQLI_SCANNER_MODULE_LEGACY,
        details={"inj_path": target, "sqli_findings": sqli_rows},
        message="sqli_confirmed",
    )
    row = _find_branch(kb, bid) if bid else None
    if row:
        row["status"] = STATUS_PARKED
        row["depth"] = DEPTH_LIGHT
        row["parked_reason"] = "sqli_confirmed_signal"
    return bid


def has_sqli_shell_pressure(kb: Mapping[str, Any]) -> bool:
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    return bool(
        parked_sqli_branches(kb)
        or "sqli_confirmed" in signals
        or "sql_signal" in signals
    )


def should_keep_shell_goal_over_auth(kb: Mapping[str, Any], operator_goal: str) -> bool:
    """Operator obtain-shell should not be demoted to obtain_auth by login surface alone."""
    return is_shell_operator_goal(operator_goal)


def module_allowed_despite_observed(kb: Mapping[str, Any], module_path: str) -> bool:
    """Resumed deep modules may run even if a light scanner was already observed."""
    if module_path != HTTP_SQLI_POST_MODULE:
        return False
    return bool(parked_sqli_branches(kb))
