#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Engagement graph persisted per workspace.

Scanner results, findings, jobs, sessions, and operator decisions are written
here as schema v1 records. A later run on the same workspace resumes from the
last proven fact instead of an empty plan.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional

from core.schemas import SCHEMA_VERSION
from core.schemas.validation import SchemaValidationError, jsonschema_available, validate_instance

_COLLECTIONS = ("targets", "evidence", "findings", "jobs", "sessions", "decisions")
_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
_TOOL_KINDS = {"http", "network", "command", "credential", "file", "log", "output", "response", "request"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _digest(*parts: Any, prefix: str) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_graph_", suffix=".json", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _check(entity: str, record: Dict[str, Any]) -> Dict[str, Any]:
    if jsonschema_available():
        validate_instance(entity, record)
    return record


class EngagementGraph:
    """JSON document of schema-v1 mission entities for one workspace."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.document: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "targets": {},
            "evidence": {},
            "findings": {},
            "jobs": {},
            "sessions": {},
            "decisions": {},
            "cursor": {"last_proven_fact_id": "", "facts": []},
        }
        self.load()

    @classmethod
    def open(cls, paths: Any) -> "EngagementGraph":
        memory = getattr(paths, "memory_dir", None)
        if memory is None:
            root = Path(os.path.expanduser("~/.kittysploit/agent/default/memory"))
        else:
            root = Path(memory)
        return cls(root / "engagement_graph.json")

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        for key in _COLLECTIONS:
            rows = payload.get(key)
            if isinstance(rows, dict):
                self.document[key] = rows
        cursor = payload.get("cursor")
        if isinstance(cursor, dict):
            self.document["cursor"] = cursor

    def save(self) -> None:
        _atomic_write(self.path, self.document)

    def upsert(self, collection: str, record: Mapping[str, Any]) -> Dict[str, Any]:
        if collection not in _COLLECTIONS:
            raise KeyError(collection)
        row = dict(record)
        entity_id = str(row.get("id") or "")
        if not entity_id:
            raise ValueError(f"{collection} record requires id")
        checked = _check(_entity_name(collection), row)
        self.document[collection][entity_id] = checked
        return checked

    def records(self, collection: str) -> List[Dict[str, Any]]:
        rows = self.document.get(collection) or {}
        if not isinstance(rows, dict):
            return []
        return [dict(row) for row in rows.values() if isinstance(row, dict)]

    def remember_approval(self, run_id: str, risk: str, *, goal: str = "") -> Dict[str, Any]:
        token = str(risk or "").strip().lower()
        return self._decision(
            run_id,
            intervention="approve_risk",
            reason=f"approve-risk {token}",
            policy_result="approved",
            confidence=1.0,
            goal=goal,
            action_type="prioritize",
            action_risk=token if token in {"read", "active", "intrusive", "destructive"} else "read",
            approved=True,
            extra={"risk": token},
        )

    def remember_refusal(
        self,
        run_id: str,
        *,
        reason: str,
        module_path: str = "",
        target: str = "",
        goal: str = "",
    ) -> Dict[str, Any]:
        return self._decision(
            run_id,
            intervention="refusal",
            reason=reason,
            policy_result="denied",
            confidence=1.0,
            goal=goal,
            action_type="skip",
            action_risk="read",
            approved=False,
            path=module_path,
            extra={"module_path": module_path, "target": target},
        )

    def remember_target_correction(
        self,
        run_id: str,
        source: str,
        corrected: str,
        *,
        goal: str = "",
    ) -> Dict[str, Any]:
        return self._decision(
            run_id,
            intervention="target_correction",
            reason=f"target corrected from {source} to {corrected}",
            policy_result="corrected",
            confidence=1.0,
            goal=goal,
            action_type="prioritize",
            action_risk="read",
            approved=True,
            extra={"source_target": str(source or ""), "corrected_target": str(corrected or "")},
        )

    def remembered_approvals(self) -> List[str]:
        revoked = {
            str((row.get("risk") or "")).strip().lower()
            for row in self._latest_by_key("revoke_risk")
            if str(row.get("policy_result") or "") == "revoked"
        }
        approved: List[str] = []
        for row in self._latest_by_key("approve_risk"):
            if str(row.get("policy_result") or "") != "approved":
                continue
            risk = str(row.get("risk") or "").strip().lower()
            if risk and risk not in revoked and risk not in approved:
                approved.append(risk)
        return approved

    def remembered_refusals(self) -> List[str]:
        paths: List[str] = []
        for row in self.records("decisions"):
            if str(row.get("intervention") or "") != "refusal":
                continue
            path = str(row.get("module_path") or "").strip()
            if path and path not in paths:
                paths.append(path)
        return paths

    def corrected_target(self, requested: str) -> str:
        requested_text = str(requested or "").strip()
        if not requested_text:
            return ""
        latest = ""
        latest_at = ""
        for row in self.records("decisions"):
            if str(row.get("intervention") or "") != "target_correction":
                continue
            source = str(row.get("source_target") or "").strip()
            corrected = str(row.get("corrected_target") or "").strip()
            created = str(row.get("created_at") or "")
            if source == requested_text and corrected and created >= latest_at:
                latest = corrected
                latest_at = created
        return latest

    def proven_findings(self, *, target_key: str = "") -> List[Dict[str, Any]]:
        key = str(target_key or "").strip().lower()
        rows: List[Dict[str, Any]] = []
        for finding in self.records("findings"):
            meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
            if not meta.get("proven"):
                continue
            if key:
                aliases = {str(item).strip().lower() for item in (meta.get("target_aliases") or [])}
                if key not in aliases:
                    continue
            rows.append(finding)
        rows.sort(key=lambda row: str((row.get("metadata") or {}).get("proven_at") or ""))
        return rows

    def last_proven_fact(self, *, target_key: str = "") -> Optional[Dict[str, Any]]:
        facts = self.proven_findings(target_key=target_key)
        if not facts:
            return None
        finding = facts[-1]
        meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        return {
            "id": str(finding.get("id") or ""),
            "summary": str(finding.get("title") or ""),
            "module_path": str(meta.get("module_path") or ""),
            "proven_at": str(meta.get("proven_at") or ""),
            "finding": finding,
        }

    def project_state(self, state: Any, phase: str) -> None:
        """Write the live agent state into this graph. Callers save afterwards."""
        target = _target_record(state)
        if target:
            self.upsert("targets", target)
        job = _job_record(state, phase, target_id=str((target or {}).get("id") or ""))
        self.upsert("jobs", job)
        aliases = _target_aliases(state, target)
        for finding in _finding_sources(state):
            evidence_ids = []
            for evidence in _evidence_records(finding, state):
                self.upsert("evidence", evidence)
                evidence_ids.append(evidence["id"])
            record = _finding_record(finding, state, evidence_ids, aliases)
            stored = self.upsert("findings", record)
            if (stored.get("metadata") or {}).get("proven"):
                self._note_fact(stored)
        for session in _session_records(state, target):
            self.upsert("sessions", session)

    def _note_fact(self, finding: Mapping[str, Any]) -> None:
        cursor = self.document.setdefault("cursor", {"last_proven_fact_id": "", "facts": []})
        fact_id = str(finding.get("id") or "")
        facts = cursor.setdefault("facts", [])
        if not any(isinstance(row, dict) and row.get("id") == fact_id for row in facts):
            meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
            facts.append({
                "id": fact_id,
                "summary": str(finding.get("title") or ""),
                "module_path": str(meta.get("module_path") or ""),
                "proven_at": str(meta.get("proven_at") or ""),
            })
        cursor["last_proven_fact_id"] = fact_id

    def _decision(
        self,
        run_id: str,
        *,
        intervention: str,
        reason: str,
        policy_result: str,
        confidence: float,
        goal: str,
        action_type: str,
        action_risk: str,
        approved: bool,
        path: str = "",
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = dict(extra or {})
        identity = _digest(intervention, reason, payload.get("risk"), payload.get("module_path"), payload.get("source_target"), payload.get("corrected_target"), prefix="decision")
        action_id = _digest(identity, "action", prefix="action")
        record: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "id": identity,
            "run_id": str(run_id or "workspace"),
            "created_at": _now(),
            "source": "operator",
            "goal": goal or None,
            "confidence": max(0.0, min(1.0, float(confidence))),
            "selected_action": {
                "schema_version": SCHEMA_VERSION,
                "id": action_id,
                "type": action_type,
                "path": path or None,
                "priority": 1,
                "risk": action_risk,
                "approval_required": True,
                "approved": approved,
                "expected_requests": 0,
                "options": {},
                "reason": reason,
                "status": "approved" if approved else "blocked",
            },
            "alternatives": [],
            "evidence": [],
            "reason": reason,
            "policy_result": policy_result,
            "intervention": intervention,
        }
        record.update(payload)
        stored = self.upsert("decisions", record)
        self.save()
        return stored

    def _latest_by_key(self, intervention: str) -> List[Dict[str, Any]]:
        rows = [
            row for row in self.records("decisions")
            if str(row.get("intervention") or "") == intervention
        ]
        rows.sort(key=lambda row: str(row.get("created_at") or ""))
        return rows


def project_agent_state(state: Any, phase: str) -> Optional[EngagementGraph]:
    """Project one agent phase into the workspace engagement graph."""
    store = getattr(state, "run_store", None)
    paths = getattr(store, "paths", None)
    if paths is None:
        return None
    try:
        graph = EngagementGraph.open(paths)
        graph.project_state(state, phase)
        graph.save()
        return graph
    except (OSError, SchemaValidationError, ValueError, TypeError):
        return None


def _entity_name(collection: str) -> str:
    return {
        "targets": "target",
        "evidence": "evidence",
        "findings": "finding",
        "jobs": "job",
        "sessions": "session",
        "decisions": "agent_decision",
    }[collection]


def _target_aliases(state: Any, target: Optional[Mapping[str, Any]]) -> List[str]:
    values = [
        str(getattr(state, "raw_target", "") or ""),
        str((target or {}).get("raw") or ""),
        str((target or {}).get("host") or ""),
        str((target or {}).get("hostname") or ""),
        str((target or {}).get("url") or ""),
    ]
    info = getattr(state, "target_info", None)
    if isinstance(info, Mapping):
        values.extend(str(info.get(key) or "") for key in ("url", "hostname", "host", "address"))
    aliases: List[str] = []
    for value in values:
        text = value.strip().lower()
        if text and text not in aliases:
            aliases.append(text)
    return aliases


def _target_record(state: Any) -> Optional[Dict[str, Any]]:
    raw = str(getattr(state, "raw_target", "") or "").strip()
    info = getattr(state, "target_info", None)
    info = info if isinstance(info, Mapping) else {}
    if not raw and not info:
        return None
    host = str(info.get("hostname") or info.get("host") or "").strip()
    url = str(info.get("url") or "").strip()
    kind = "url" if url else ("host" if host else "unknown")
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": _digest(raw or host or url, prefix="target"),
        "type": kind,
        "raw": raw or url or host or "unknown",
    }
    if url:
        record["url"] = url
    if host:
        record["host"] = host
        record["hostname"] = host
    scheme = str(info.get("scheme") or "").strip()
    if scheme:
        record["scheme"] = scheme
    port = info.get("port")
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        port_num = 0
    if 1 <= port_num <= 65535:
        record["port"] = port_num
    record["metadata"] = {"run_id": str(getattr(state, "run_id", "") or "")}
    return record


def _job_record(state: Any, phase: str, *, target_id: str) -> Dict[str, Any]:
    run_id = str(getattr(state, "run_id", "") or "run")
    phase_name = str(phase or getattr(state, "current_phase", "") or "init")
    status = "failed" if getattr(state, "error", None) else "completed"
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": _digest(run_id, phase_name, prefix="job"),
        "name": f"agent:{phase_name}",
        "status": status,
        "metadata": {
            "run_id": run_id,
            "phase": phase_name,
            "workspace": str(getattr(state, "workspace", "") or ""),
        },
    }
    if target_id:
        record["metadata"]["target_id"] = target_id
    return record


def _finding_sources(state: Any) -> Iterable[Mapping[str, Any]]:
    seen: set[str] = set()
    buckets = (
        getattr(state, "contextual_findings", None),
        getattr(state, "vulnerable_results", None),
        getattr(state, "results", None),
    )
    for bucket in buckets:
        if not isinstance(bucket, list):
            continue
        for row in bucket:
            if not isinstance(row, Mapping):
                continue
            key = "|".join([
                str(row.get("path") or row.get("module") or ""),
                str(row.get("message") or "")[:180],
                str(row.get("exploit_module") or ""),
            ])
            if key in seen:
                continue
            seen.add(key)
            yield row


def _evidence_records(finding: Mapping[str, Any], state: Any) -> List[Dict[str, Any]]:
    records = finding.get("evidence_records")
    if not isinstance(records, list):
        records = []
    built: List[Dict[str, Any]] = []
    module_path = str(finding.get("path") or finding.get("module") or "module")
    for index, row in enumerate(records):
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind") or "log").lower()
        if kind not in {
            "http", "command", "file", "screenshot", "credential", "session",
            "network", "proxy_flow", "log", "artifact", "agent_report", "manual", "note", "other",
        }:
            kind = "log" if kind in _TOOL_KINDS else "note"
        summary = str(row.get("summary") or row.get("content_preview") or row.get("message") or "").strip()
        if not summary:
            continue
        built.append({
            "schema_version": SCHEMA_VERSION,
            "id": _digest(module_path, kind, summary[:120], index, prefix="evidence"),
            "kind": kind,
            "title": summary[:180] or kind,
            "metadata": {
                "run_id": str(getattr(state, "run_id", "") or ""),
                "module_path": module_path,
            },
        })
    return built


def _finding_record(
    finding: Mapping[str, Any],
    state: Any,
    evidence_ids: List[str],
    aliases: List[str],
) -> Dict[str, Any]:
    message = str(finding.get("message") or finding.get("title") or finding.get("path") or "finding").strip()
    module_path = str(finding.get("path") or finding.get("module") or "").strip()
    exploit_module = str(finding.get("exploit_module") or "").strip()
    severity = str(finding.get("severity") or "unknown").lower()
    if severity not in _SEVERITIES:
        severity = "unknown"
    vulnerable = bool(finding.get("vulnerable"))
    gate = finding.get("evidence_gate") if isinstance(finding.get("evidence_gate"), dict) else {}
    proven = bool(gate.get("passed")) and str(gate.get("provenance") or "") == "tool"
    try:
        confidence = float(finding.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": _digest(module_path, message[:160], exploit_module, prefix="finding"),
        "title": message[:240] or "finding",
        "severity": severity,
        "status": "affected" if vulnerable else "informational",
        "evidence": evidence_ids,
        "confidence": confidence,
        "metadata": {
            "run_id": str(getattr(state, "run_id", "") or ""),
            "module_path": module_path,
            "exploit_module": exploit_module,
            "decision_class": str(finding.get("decision_class") or ""),
            "evidence_gate": dict(gate),
            "evidence_state": str(finding.get("evidence_state") or ""),
            "proven": proven,
            "proven_at": _now() if proven else "",
            "target_aliases": aliases,
        },
    }
    if module_path:
        record["module"] = {"path": module_path}
    raw_target = str(getattr(state, "raw_target", "") or "").strip()
    if raw_target:
        record["target"] = raw_target
    return record


def _session_records(state: Any, target: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for session_id in list(getattr(state, "new_sessions", None) or []):
        text = str(session_id or "").strip()
        if not text:
            continue
        record: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "id": _digest(text, prefix="session"),
            "session_id": text[:256],
            "session_type": "shell",
            "is_active": True,
            "metadata": {"run_id": str(getattr(state, "run_id", "") or "")},
        }
        if target and target.get("id"):
            record["target"] = str(target.get("raw") or target.get("id"))
        rows.append(record)
    return rows


def agent_finding_from_graph(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Rebuild the agent finding dict the planner already consumes."""
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    gate = meta.get("evidence_gate") if isinstance(meta.get("evidence_gate"), dict) else {}
    proven = bool(meta.get("proven"))
    return {
        "path": str(meta.get("module_path") or ""),
        "module": str(meta.get("module_path") or ""),
        "message": str(finding.get("title") or ""),
        "vulnerable": str(finding.get("status") or "") == "affected",
        "severity": str(finding.get("severity") or "unknown"),
        "exploit_module": str(meta.get("exploit_module") or ""),
        "decision_class": str(meta.get("decision_class") or ""),
        "evidence_gate": dict(gate),
        "gate_blocked": not bool(gate.get("passed")),
        "evidence_state": "confirmed" if proven else str(meta.get("evidence_state") or "signal"),
        "confidence": finding.get("confidence") or 0.0,
        "resumed_from_graph": True,
    }
