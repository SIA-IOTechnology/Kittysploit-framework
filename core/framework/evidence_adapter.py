#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize ``ModuleResult`` evidence into json/v1 Evidence records."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from core.framework.base_module import ModuleResult, normalize_module_result
from core.framework.finding_adapter import (
    link_evidence_to_finding,
    module_result_to_finding,
)
from core.schemas import SCHEMA_VERSION
from core.schemas.validation import (
    SchemaValidationError,
    validate_evidence_records,
    validate_finding_record,
)

_EVIDENCE_KINDS = frozenset(
    {
        "http",
        "command",
        "file",
        "screenshot",
        "credential",
        "session",
        "network",
        "proxy_flow",
        "log",
        "artifact",
        "agent_report",
        "manual",
        "note",
        "other",
    }
)

_SOURCE_TYPES = frozenset(
    {"module", "proxy", "session", "agent", "manual", "api", "mcp", "plugin", "external", "unknown"}
)

_SCHEMA_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "kind",
        "type",
        "title",
        "summary",
        "content_preview",
        "collected_at",
        "target",
        "workspace",
        "source",
        "module",
        "job_id",
        "session_id",
        "finding_id",
        "ref_id",
        "path",
        "request",
        "response",
        "command",
        "artifact",
        "redaction",
        "chain_of_custody",
        "confidence",
        "tags",
        "metadata",
    }
)

_TARGET_OPTION_NAMES = (
    "target",
    "rhost",
    "rhosts",
    "host",
    "hostname",
    "url",
    "RHOST",
    "RHOSTS",
    "HOST",
)


def _new_evidence_id() -> str:
    return f"ev_{uuid.uuid4().hex[:12]}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _option_value(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "value"):
        return value.value
    return value


def _target_from_module(module: Any) -> Optional[str]:
    if module is None:
        return None
    for name in _TARGET_OPTION_NAMES:
        if not hasattr(module, name):
            continue
        raw = _option_value(getattr(module, name))
        if raw is None:
            continue
        text = str(raw).strip()
        if text and text.lower() != "none":
            return text
    return None


def _module_path(module: Any, module_path: str = "") -> str:
    if module_path:
        return module_path.strip()
    if module is None:
        return ""
    for attr in ("module_path", "path"):
        candidate = getattr(module, attr, None)
        if candidate:
            return str(candidate).strip()
    raw = str(getattr(module, "__module__", "") or "")
    for prefix in ("modules.auxiliary.", "modules."):
        if raw.startswith(prefix):
            return raw[len(prefix) :].replace(".", "/")
    return raw.replace(".", "/")


def _module_name(module: Any, module_path: str = "") -> str:
    if module is None:
        return module_path or "unknown"
    info = getattr(module, "__info__", {}) or {}
    return (
        str(getattr(module, "name", "") or info.get("name") or module_path or "unknown").strip()
        or "unknown"
    )


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


def _title_from_finding(finding: Any, *, fallback: str) -> str:
    if isinstance(finding, dict):
        for key in ("title", "name", "summary", "reason", "message"):
            value = finding.get(key)
            if value:
                return str(value).strip()[:256] or fallback
    if isinstance(finding, str) and finding.strip():
        return finding.strip()[:256]
    return fallback


def _is_complete_schema_evidence(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if not str(record.get("id") or "").strip():
        return False
    if not str(record.get("title") or "").strip():
        return False
    kind = record.get("kind") or record.get("type")
    return bool(kind)


def _pick_schema_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    return {key: record[key] for key in _SCHEMA_EVIDENCE_KEYS if key in record}


def _infer_kind(item: Any, record: Dict[str, Any]) -> str:
    kind = str(record.get("kind") or record.get("type") or "").strip().lower()
    if kind in _EVIDENCE_KINDS:
        return kind
    if record.get("request") or record.get("response"):
        return "http"
    if record.get("command"):
        return "command"
    if record.get("artifact"):
        return "artifact"
    if isinstance(item, dict):
        if item.get("request_url") or item.get("status_code") is not None:
            return "http"
        if item.get("stdout") is not None or item.get("stderr") is not None:
            return "command"
        hinted = str(item.get("kind") or item.get("type") or "").strip().lower()
        if hinted in _EVIDENCE_KINDS:
            return hinted
    text = str(record.get("summary") or record.get("content_preview") or "").lower()
    if text.startswith(("get ", "post ", "put ", "delete ", "patch ", "head ", "options ")):
        return "http"
    if any(token in text for token in ("tcp/", "udp/", "port ", "banner")):
        return "network"
    return "note" if isinstance(item, str) else "other"


def _http_fields_from_legacy(item: Dict[str, Any]) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    request_url = str(item.get("request_url") or item.get("url") or "").strip()
    method = str(item.get("method") or item.get("http_method") or "GET").strip().upper() or "GET"
    if request_url:
        fields["request"] = {
            "method": method,
            "url": request_url,
            "headers": dict(item.get("request_headers") or {}),
        }
        body = item.get("request_body")
        if body is not None:
            fields["request"]["body_text"] = str(body)

    status_code = item.get("status_code")
    if status_code is not None:
        try:
            status_code = int(status_code)
        except (TypeError, ValueError):
            status_code = None
    response_body = item.get("response_body")
    if response_body is None:
        response_body = item.get("evidence_snippet") or item.get("body_text")
    if status_code is not None or response_body is not None or item.get("response_time") is not None:
        response: Dict[str, Any] = {}
        if status_code is not None:
            response["status_code"] = status_code
        if response_body is not None:
            response["body_text"] = str(response_body)[:8000]
        elapsed = item.get("response_time") or item.get("response_time_s") or item.get("elapsed_ms")
        if elapsed is not None:
            try:
                elapsed_value = float(elapsed)
                if "elapsed_ms" not in item and elapsed_value < 1000:
                    elapsed_value *= 1000.0
                response["elapsed_ms"] = elapsed_value
            except (TypeError, ValueError):
                pass
        fields["response"] = response
    return fields


def _summary_from_item(item: Any, record: Dict[str, Any]) -> Optional[str]:
    for key in ("summary", "content_preview", "evidence_snippet", "message", "detail", "description"):
        if isinstance(item, dict) and item.get(key):
            return str(item[key]).strip()[:4000] or None
        if record.get(key):
            return str(record[key]).strip()[:4000] or None
    if isinstance(item, str):
        text = item.strip()
        return text[:4000] if text else None
    return None


def _coerce_evidence_item(
    item: Any,
    *,
    index: int,
    module: Any,
    module_path: str,
    workspace: Optional[str],
    target: Any,
    finding: Any,
    session_id: Optional[str],
    job_id: Optional[Any],
) -> Optional[Dict[str, Any]]:
    if item is None:
        return None

    if isinstance(item, dict) and _is_complete_schema_evidence(item):
        record = _pick_schema_fields(item)
        record.setdefault("schema_version", SCHEMA_VERSION)
        if not record.get("collected_at"):
            record["collected_at"] = _utc_now()
        if workspace and not record.get("workspace"):
            record["workspace"] = workspace
        if session_id and not record.get("session_id"):
            record["session_id"] = session_id
        if job_id is not None and record.get("job_id") is None:
            record["job_id"] = job_id
        if target and not record.get("target"):
            record["target"] = target
        if not record.get("source"):
            path = _module_path(module, module_path)
            record["source"] = {"name": path or _module_name(module, module_path), "type": "module"}
        if not record.get("module"):
            path = _module_path(module, module_path)
            record["module"] = {
                "path": path or _module_name(module, module_path),
                "name": _module_name(module, module_path),
                "type": _module_type(module),
            }
        record.setdefault("metadata", {})
        if record.get("kind") is None and record.get("type"):
            record["kind"] = str(record["type"])
        return record

    base_title = _title_from_finding(finding, fallback=_module_name(module, module_path))
    record: Dict[str, Any] = {}
    if isinstance(item, dict):
        record.update(_pick_schema_fields(item))
        record.update(_http_fields_from_legacy(item))

    summary = _summary_from_item(item, record)
    if summary and not record.get("summary"):
        record["summary"] = summary
    if not record.get("content_preview") and summary and len(summary) > 240:
        record["content_preview"] = summary[:240]

    kind = _infer_kind(item, record)
    record["kind"] = kind
    record.pop("type", None)

    title = str(record.get("title") or "").strip()
    if not title:
        title = _title_from_finding(finding, fallback="")
        if not title and isinstance(item, dict):
            for key in ("title", "name", "injection_type", "param"):
                if item.get(key):
                    title = str(item[key]).strip()
                    break
        if not title and summary:
            title = summary.splitlines()[0][:120]
        if not title:
            title = base_title if index == 0 else f"{base_title} ({index + 1})"
    record["title"] = title[:256]

    record["schema_version"] = SCHEMA_VERSION
    record["id"] = str(record.get("id") or _new_evidence_id())
    record["collected_at"] = record.get("collected_at") or _utc_now()
    if workspace:
        record["workspace"] = workspace
    if target:
        record["target"] = target
    if session_id:
        record["session_id"] = session_id
    if job_id is not None:
        record["job_id"] = job_id

    path = _module_path(module, module_path)
    record["source"] = record.get("source") or {
        "name": path or _module_name(module, module_path),
        "type": "module",
    }
    if isinstance(record["source"], dict):
        source_type = str(record["source"].get("type") or "module").lower()
        if source_type not in _SOURCE_TYPES:
            record["source"]["type"] = "module"

    record["module"] = record.get("module") or {
        "path": path or _module_name(module, module_path),
        "name": _module_name(module, module_path),
        "type": _module_type(module),
    }
    record.setdefault("metadata", {})
    return record


def _evidence_items(raw: Any) -> List[Any]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        return [item for item in raw if item is not None]
    return [raw]


def module_result_to_evidence(
    result: Union[ModuleResult, Any],
    *,
    module: Any = None,
    module_path: str = "",
    workspace: Optional[str] = None,
    target: Any = None,
    finding: Any = None,
    session_id: Optional[str] = None,
    job_id: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Convert a module result's evidence payload into schema Evidence dicts."""
    normalized = normalize_module_result(result)
    raw_items = _evidence_items(normalized.evidence)
    if not raw_items and isinstance(normalized.data, dict):
        raw_items = _evidence_items(normalized.data.get("evidence"))

    if target is None:
        target = _target_from_module(module)
    if finding is None:
        finding = normalized.finding
    if session_id is None:
        session_id = normalized.session_id

    records: List[Dict[str, Any]] = []
    for index, item in enumerate(raw_items):
        record = _coerce_evidence_item(
            item,
            index=index,
            module=module,
            module_path=module_path,
            workspace=workspace,
            target=target,
            finding=finding,
            session_id=session_id,
            job_id=job_id,
        )
        if record:
            records.append(record)
    return records


def attach_schema_evidence(
    execution: Any,
    *,
    module: Any = None,
    framework: Any = None,
    module_path: str = "",
) -> Any:
    """Populate ``schema_evidence`` and ``schema_finding`` on a module execution result."""
    workspace: Optional[str] = None
    if framework is not None and hasattr(framework, "get_current_workspace_name"):
        try:
            workspace = framework.get_current_workspace_name()
        except Exception:
            workspace = None

    normalized = normalize_module_result(execution.result)
    raw_finding = execution.finding if execution.finding is not None else normalized.finding
    target = _target_from_module(module)

    schema_evidence = module_result_to_evidence(
        normalized,
        module=module,
        module_path=module_path,
        workspace=workspace,
        target=target,
        finding=raw_finding,
        session_id=execution.session_id or normalized.session_id,
    )

    schema_finding = module_result_to_finding(
        normalized,
        module=module,
        module_path=module_path,
        workspace=workspace,
        target=target,
        finding=raw_finding,
        schema_evidence=schema_evidence,
        session_id=execution.session_id or normalized.session_id,
    )
    if schema_finding:
        finding_id = str(schema_finding["id"])
        schema_evidence = link_evidence_to_finding(schema_evidence, finding_id)
        if schema_finding.get("evidence") != schema_evidence:
            schema_finding = dict(schema_finding)
            schema_finding["evidence"] = list(schema_evidence)

    validation_errors: List[str] = []
    if schema_evidence:
        try:
            schema_evidence = validate_evidence_records(schema_evidence)
        except SchemaValidationError as exc:
            validation_errors.extend(exc.errors)
    if schema_finding and not validation_errors:
        try:
            schema_finding = validate_finding_record(schema_finding)
        except SchemaValidationError as exc:
            validation_errors.extend(exc.errors)

    if validation_errors:
        execution.schema_validation_ok = False
        execution.schema_validation_errors = validation_errors
        execution.schema_evidence = []
        execution.schema_finding = None
        return execution

    execution.schema_validation_ok = True
    execution.schema_validation_errors = []
    execution.schema_evidence = schema_evidence
    execution.schema_finding = schema_finding
    return execution
