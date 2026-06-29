#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize ``ModuleResult`` findings and link schema Evidence records."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Union

from core.framework.base_module import ModuleResult, normalize_module_result
from core.schemas import SCHEMA_VERSION

_SEVERITY_VALUES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
_STATUS_VALUES = frozenset(
    {
        "affected",
        "not_affected",
        "fixed",
        "under_investigation",
        "open",
        "triaged",
        "accepted_risk",
        "false_positive",
        "informational",
        "closed",
        "unknown",
    }
)

_SCHEMA_FINDING_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "title",
        "description",
        "category",
        "severity",
        "status",
        "cve",
        "cwe",
        "cvss_score",
        "affected_targets",
        "target",
        "evidence",
        "remediation",
        "module",
        "job_id",
        "session_id",
        "references",
        "confidence",
        "exploitability",
        "first_seen",
        "last_seen",
        "retest",
        "tags",
        "metadata",
    }
)

_SEVERITY_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "unknown",
}


def _new_finding_id() -> str:
    return f"finding_{uuid.uuid4().hex[:12]}"


def _pick_schema_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    return {key: record[key] for key in _SCHEMA_FINDING_KEYS if key in record}


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "medium"
    mapped = _SEVERITY_ALIASES.get(text, text)
    return mapped if mapped in _SEVERITY_VALUES else "unknown"


def _normalize_status(value: Any, *, success: bool) -> str:
    text = str(value or "").strip().lower()
    if text in _STATUS_VALUES:
        return text
    return "affected" if success else "informational"


def _is_complete_schema_finding(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if not str(record.get("id") or "").strip():
        return False
    if not str(record.get("title") or "").strip():
        return False
    severity = str(record.get("severity") or "").strip().lower()
    status = str(record.get("status") or "").strip().lower()
    return severity in _SEVERITY_VALUES and status in _STATUS_VALUES


def _title_from_raw_finding(raw_finding: Any, *, fallback: str) -> str:
    if isinstance(raw_finding, dict):
        for key in ("title", "name", "summary", "reason", "message"):
            value = raw_finding.get(key)
            if value:
                return str(value).strip()[:256]
    if isinstance(raw_finding, str) and raw_finding.strip():
        return raw_finding.strip()[:256]
    return fallback


def _description_from_raw_finding(raw_finding: Any) -> Optional[str]:
    if not isinstance(raw_finding, dict):
        return None
    for key in ("description", "detail", "message", "reason"):
        value = raw_finding.get(key)
        if value:
            return str(value).strip()[:8000]
    return None


def finding_is_applicable(
    result: Union[ModuleResult, Any],
    *,
    finding: Any = None,
    schema_evidence: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """Return whether the module result should produce a schema Finding."""
    normalized = normalize_module_result(result)
    raw_finding = finding if finding is not None else normalized.finding
    if raw_finding is None:
        return False
    if isinstance(raw_finding, str) and not raw_finding.strip():
        return False
    if isinstance(raw_finding, dict) and not raw_finding and not schema_evidence:
        return False
    return True


def link_evidence_to_finding(
    schema_evidence: List[Dict[str, Any]],
    finding_id: str,
) -> List[Dict[str, Any]]:
    """Attach ``finding_id`` to each schema Evidence record."""
    linked: List[Dict[str, Any]] = []
    for record in schema_evidence:
        item = dict(record)
        item["finding_id"] = finding_id
        linked.append(item)
    return linked


def module_result_to_finding(
    result: Union[ModuleResult, Any],
    *,
    module: Any = None,
    module_path: str = "",
    workspace: Optional[str] = None,
    target: Any = None,
    finding: Any = None,
    schema_evidence: Optional[List[Dict[str, Any]]] = None,
    session_id: Optional[str] = None,
    job_id: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """Convert a module result finding payload into a schema Finding dict."""
    normalized = normalize_module_result(result)
    raw_finding = finding if finding is not None else normalized.finding
    if not finding_is_applicable(normalized, finding=raw_finding, schema_evidence=schema_evidence):
        return None

    evidence_rows = list(schema_evidence or [])
    module_ref = _module_ref(module, module_path)

    if isinstance(raw_finding, dict) and _is_complete_schema_finding(raw_finding):
        record = _pick_schema_fields(raw_finding)
        record.setdefault("schema_version", SCHEMA_VERSION)
        finding_id = str(record["id"])
        if evidence_rows and not record.get("evidence"):
            record["evidence"] = list(evidence_rows)
        if target and not record.get("target"):
            record["target"] = target
        if target and not record.get("affected_targets"):
            record["affected_targets"] = [target]
        if session_id and not record.get("session_id"):
            record["session_id"] = session_id
        if job_id is not None and record.get("job_id") is None:
            record["job_id"] = job_id
        if not record.get("module"):
            record["module"] = module_ref
        record.setdefault("metadata", {})
        if workspace:
            metadata = dict(record.get("metadata") or {})
            metadata.setdefault("workspace", workspace)
            record["metadata"] = metadata
        return record

    fallback_title = _module_name(module, module_path)
    title = _title_from_raw_finding(raw_finding, fallback=fallback_title)
    description = _description_from_raw_finding(raw_finding)
    severity = "medium"
    status = _normalize_status(None, success=normalized.success)
    cve = None
    cwe = None
    references: List[str] = []
    tags: List[str] = []

    if isinstance(raw_finding, dict):
        severity = _normalize_severity(raw_finding.get("severity") or raw_finding.get("risk"))
        status = _normalize_status(raw_finding.get("status"), success=normalized.success)
        cve = raw_finding.get("cve")
        cwe = raw_finding.get("cwe")
        refs = raw_finding.get("references")
        if isinstance(refs, list):
            references = [str(item) for item in refs if item]
        tag_values = raw_finding.get("tags")
        if isinstance(tag_values, list):
            tags = [str(item) for item in tag_values if item]
        if raw_finding.get("id"):
            finding_id = str(raw_finding["id"])
        else:
            finding_id = _new_finding_id()
    else:
        finding_id = _new_finding_id()

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": finding_id,
        "title": title,
        "severity": severity,
        "status": status,
        "evidence": list(evidence_rows),
        "metadata": {"workspace": workspace} if workspace else {},
    }
    if description:
        record["description"] = description
    if target:
        record["target"] = target
        record["affected_targets"] = [target]
    if session_id:
        record["session_id"] = session_id
    if job_id is not None:
        record["job_id"] = job_id
    if module_ref:
        record["module"] = module_ref
    if cve:
        record["cve"] = cve
    if cwe:
        record["cwe"] = cwe
    if references:
        record["references"] = references
    if tags:
        record["tags"] = tags
    return record


def _module_name(module: Any, module_path: str = "") -> str:
    if module is None:
        return module_path or "unknown"
    info = getattr(module, "__info__", {}) or {}
    return (
        str(getattr(module, "name", "") or info.get("name") or module_path or "unknown").strip()
        or "unknown"
    )


def _module_path(module: Any, module_path: str = "") -> str:
    if module_path:
        return module_path.strip()
    if module is None:
        return ""
    raw = str(getattr(module, "__module__", "") or "")
    for prefix in ("modules.auxiliary.", "modules."):
        if raw.startswith(prefix):
            return raw[len(prefix) :].replace(".", "/")
    return raw.replace(".", "/")


def _module_ref(module: Any, module_path: str = "") -> Union[str, Dict[str, Any]]:
    path = _module_path(module, module_path)
    if not module and not path:
        return ""
    return {
        "path": path or _module_name(module, module_path),
        "name": _module_name(module, module_path),
        "type": _module_type(module),
    }


def _module_type(module: Any) -> str:
    if module is None:
        return "module"
    info = getattr(module, "__info__", {}) or {}
    return str(
        getattr(module, "TYPE_MODULE", None)
        or getattr(module, "type", None)
        or info.get("type")
        or "module"
    ).lower()
