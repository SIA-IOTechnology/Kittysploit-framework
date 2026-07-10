#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Promotional evidence model for agent findings.

This module intentionally stays lightweight: it can consume full schema
Evidence records when the framework provides them, or synthesize compact
evidence records from legacy scanner rows.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from core.schemas import SCHEMA_VERSION
except Exception:  # pragma: no cover - isolated test env
    SCHEMA_VERSION = "json/v1"

try:
    from interfaces.command_system.builtin.agent.redaction import (
        redact_text,
        sanitize_nested,
    )
except Exception:  # pragma: no cover - isolated test env
    def redact_text(value: Any, limit: int = 16000) -> str:
        return str(value or "")[: max(0, int(limit))]

    def sanitize_nested(value: Any, parent_key: str = "", depth: int = 0) -> Any:
        return value

EVIDENCE_STATES = ("signal", "probable", "confirmed", "exploitable", "fixed", "regressed")
PROMOTION_ORDER = {name: index for index, name in enumerate(EVIDENCE_STATES)}
MAX_EVIDENCE_ROWS = 12
MAX_SUMMARY_LEN = 1200


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_hash(payload: Any) -> str:
    safe = sanitize_nested(payload)
    text = json.dumps(safe, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def _short(value: Any, limit: int = MAX_SUMMARY_LEN) -> str:
    return " ".join(redact_text(value, limit).split())[:limit]


def _module_name(path: str) -> str:
    path = str(path or "").strip()
    return path.rsplit("/", 1)[-1] if path else "module"


def _target_from_row(row: Dict[str, Any]) -> str:
    for key in ("url", "target", "host", "hostname"):
        value = row.get(key)
        if value:
            return str(value)[:300]
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    for key in ("request_url", "url", "target"):
        value = details.get(key)
        if value:
            return str(value)[:300]
    return ""


def _evidence_kind(row: Dict[str, Any], item: Any = None) -> str:
    if isinstance(item, dict) and item.get("kind"):
        return str(item.get("kind") or "other").lower()
    path = str(row.get("path") or "").lower()
    if "/http/" in f"/{path}/" or str(row.get("url") or "").startswith(("http://", "https://")):
        return "http"
    if any(token in path for token in ("login", "credential", "bruteforce")):
        return "credential"
    if any(token in path for token in ("shell", "rce", "exec", "command")):
        return "command"
    if any(token in path for token in ("mysql", "postgres", "redis", "smb", "ldap", "ssh", "winrm")):
        return "network"
    if str(row.get("status") or "").lower() in {"error", "blocked", "skipped"}:
        return "log"
    return "other"


def _summary_from_row(row: Dict[str, Any], item: Any = None) -> str:
    parts: List[str] = []
    if isinstance(item, dict):
        for key in ("summary", "evidence_snippet", "content_preview", "title", "message"):
            value = item.get(key)
            if value:
                parts.append(str(value))
                break
        request = item.get("request")
        response = item.get("response")
        if isinstance(request, dict):
            method = request.get("method")
            url = request.get("url") or request.get("path")
            if method or url:
                parts.append(f"request={method or 'GET'} {url or ''}".strip())
        if isinstance(response, dict) and response.get("status_code") is not None:
            parts.append(f"status={response.get('status_code')}")
    elif isinstance(item, str):
        parts.append(item)

    message = str(row.get("message") or "").strip()
    if message:
        parts.append(message)

    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    for key in (
        "reason",
        "indicator",
        "status_code",
        "param",
        "parameter",
        "payload",
        "request_url",
        "evidence_snippet",
    ):
        value = details.get(key)
        if value not in (None, ""):
            parts.append(f"{key}={value}")

    if not parts and row.get("evidence"):
        parts.append(str(row.get("evidence")))
    if not parts:
        parts.append(str(row.get("status") or "module result"))
    return _short(" | ".join(parts), MAX_SUMMARY_LEN)


def _source_record(row: Dict[str, Any]) -> Dict[str, Any]:
    path = str(row.get("path") or "")
    return {
        "name": path or str(row.get("module") or "module"),
        "type": "module",
    }


def _module_record(row: Dict[str, Any]) -> Dict[str, Any]:
    path = str(row.get("path") or "")
    return {
        "path": path,
        "name": str(row.get("module") or _module_name(path)),
        "type": path.split("/", 1)[0] if "/" in path else "module",
    }


def _is_schema_evidence(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    return bool(item.get("id") and item.get("title") and item.get("kind"))


def _coerce_evidence_item(row: Dict[str, Any], item: Any, index: int = 0) -> Dict[str, Any]:
    if _is_schema_evidence(item):
        record = dict(item)
        record.setdefault("schema_version", SCHEMA_VERSION)
        record.setdefault("collected_at", _utc_now())
        record.setdefault("source", _source_record(row))
        record.setdefault("module", _module_record(row))
        record.setdefault("target", _target_from_row(row) or None)
        record.setdefault("metadata", {})
    else:
        summary = _summary_from_row(row, item)
        digest = _canonical_hash({
            "path": row.get("path"),
            "status": row.get("status"),
            "vulnerable": row.get("vulnerable"),
            "summary": summary,
            "item": item,
        })
        record = {
            "schema_version": SCHEMA_VERSION,
            "id": f"ev_agent_{digest[:12]}",
            "kind": _evidence_kind(row, item),
            "title": str(row.get("module") or _module_name(row.get("path", "")))[:256],
            "summary": summary,
            "content_preview": summary[:240],
            "collected_at": _utc_now(),
            "target": _target_from_row(row) or None,
            "source": _source_record(row),
            "module": _module_record(row),
            "metadata": {
                "path": str(row.get("path") or ""),
                "status": str(row.get("status") or ""),
                "vulnerable": bool(row.get("vulnerable")),
                "severity": str(row.get("severity") or ""),
                "index": index,
            },
        }

    record["summary"] = _short(record.get("summary") or record.get("content_preview") or "", MAX_SUMMARY_LEN)
    if not record.get("content_preview") and record.get("summary"):
        record["content_preview"] = str(record["summary"])[:240]
    record["confidence"] = evidence_confidence(record, row)
    record["content_sha256"] = _canonical_hash(record)
    record.setdefault("chain_of_custody", [{
        "actor": "agent",
        "action": "observed",
        "at": record.get("collected_at") or _utc_now(),
        "digest_sha256": record["content_sha256"],
        "notes": f"Module result {row.get('path', '')}",
    }])
    return sanitize_nested(record)


def evidence_confidence(record: Dict[str, Any], row: Dict[str, Any]) -> float:
    """Estimate confidence of a single evidence record."""
    try:
        existing = float(record.get("confidence"))
        if existing > 0:
            return round(max(0.05, min(0.99, existing)), 3)
    except Exception:
        pass
    severity = str(row.get("severity") or "").lower()
    status = str(row.get("status") or "").lower()
    vulnerable = bool(row.get("vulnerable"))
    summary = str(record.get("summary") or "").lower()
    score = 0.48
    if vulnerable:
        score += 0.2
    if status in {"vulnerable", "affected"}:
        score += 0.08
    if severity in {"critical", "high"}:
        score += 0.08
    if any(token in summary for token in ("confirmed", "executed", "authenticated", "uid=", "status=200")):
        score += 0.1
    if any(token in summary for token in ("possible", "potential", "maybe")):
        score -= 0.08
    if status in {"error", "blocked", "skipped"}:
        score = min(score, 0.45)
    return round(max(0.05, min(0.99, score)), 3)


def evidence_records_from_result(row: Dict[str, Any], *, max_records: int = MAX_EVIDENCE_ROWS) -> List[Dict[str, Any]]:
    """Return schema-like evidence records for an agent result row."""
    if not isinstance(row, dict):
        return []
    raw_items: List[Any] = []
    schema_rows = row.get("schema_evidence")
    if isinstance(schema_rows, list):
        raw_items.extend(schema_rows)
    elif schema_rows:
        raw_items.append(schema_rows)

    raw = row.get("raw_evidence")
    if raw is None:
        raw = row.get("evidence_payload")
    if raw is not None:
        raw_items.extend(raw if isinstance(raw, list) else [raw])

    # ``evidence`` is often a dedupe string; keep it as fallback only.
    if not raw_items and row.get("evidence"):
        raw_items.append(str(row.get("evidence")))
    if not raw_items:
        raw_items.append(None)

    records: List[Dict[str, Any]] = []
    seen = set()
    for index, item in enumerate(raw_items):
        record = _coerce_evidence_item(row, item, index=index)
        digest = str(record.get("content_sha256") or record.get("id") or "")
        if digest in seen:
            continue
        records.append(record)
        seen.add(digest)
        if len(records) >= max_records:
            break
    return records


def promote_state_from_evidence(row: Dict[str, Any], evidence_rows: List[Dict[str, Any]]) -> str:
    """Promote evidence state from module result and normalized evidence rows."""
    if not isinstance(row, dict):
        return "signal"
    current = str(row.get("evidence_state") or "signal")
    independent = len({
        str((e.get("source") or {}).get("name") or e.get("id") or "")
        for e in evidence_rows
        if isinstance(e, dict)
    })
    explicit = bool(row.get("session_id") or row.get("exploit_success"))
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    if details.get("authenticated_as") or details.get("command_output") or details.get("proof"):
        explicit = True
    state = promote_evidence(
        current,
        independent_sources=independent,
        exploit_success=explicit and bool(row.get("exploit_module")),
    )
    best_confidence = max(
        [float(e.get("confidence", 0.0) or 0.0) for e in evidence_rows if isinstance(e, dict)]
        or [0.0]
    )
    if (explicit or best_confidence >= 0.82) and state in {"signal", "probable"}:
        state = "confirmed"
    if bool(row.get("exploit_module")) and state == "confirmed" and (explicit or best_confidence >= 0.82):
        state = "exploitable"
    if bool(row.get("vulnerable")) and state == "signal":
        state = initial_evidence_state(len(evidence_rows))
    return state


def attach_result_evidence(
    finding: Dict[str, Any],
    *,
    max_records: int = MAX_EVIDENCE_ROWS,
) -> Dict[str, Any]:
    """Attach normalized evidence rows and promotion fields to a finding/result."""
    if not isinstance(finding, dict):
        return finding
    out = dict(finding)
    records = evidence_records_from_result(out, max_records=max_records)
    out["evidence_records"] = records
    out["evidence_state"] = promote_state_from_evidence(out, records)
    out["confidence"] = finding_confidence_from_evidence([
        {"state": out["evidence_state"], **row}
        for row in records
    ])
    out["proof_quality"] = {
        "records": len(records),
        "independent_sources": len({
            str((row.get("source") or {}).get("name") or row.get("id") or "")
            for row in records
        }),
        "best_confidence": max(
            [float(row.get("confidence", 0.0) or 0.0) for row in records] or [0.0]
        ),
    }
    if records and not out.get("evidence"):
        out["evidence"] = records[0].get("summary") or records[0].get("content_preview")
    return out


def initial_evidence_state(signals: int = 1) -> str:
    if signals <= 0:
        return "signal"
    if signals == 1:
        return "probable"
    return "confirmed"


def promote_evidence(
    current: str,
    *,
    independent_sources: int = 0,
    exploit_success: bool = False,
    retest_fixed: bool = False,
    retest_regressed: bool = False,
) -> str:
    state = str(current or "signal").lower()
    if state not in PROMOTION_ORDER:
        state = "signal"
    if retest_regressed:
        return "regressed"
    if retest_fixed:
        return "fixed"
    if exploit_success and state in {"confirmed", "probable"}:
        return "exploitable"
    if independent_sources >= 2 and PROMOTION_ORDER[state] < PROMOTION_ORDER["confirmed"]:
        return "confirmed"
    if independent_sources == 1 and state == "signal":
        return "probable"
    return state


def finding_confidence_from_evidence(evidence_rows: List[Dict[str, Any]]) -> str:
    if not evidence_rows:
        return "probable"
    states = [str(row.get("state", "probable")).lower() for row in evidence_rows]
    best = max(states, key=lambda value: PROMOTION_ORDER.get(value, 0))
    if best in {"confirmed", "exploitable"}:
        return best
    return "probable"


def attach_evidence_to_finding(
    finding: Dict[str, Any],
    evidence: Dict[str, Any],
    *,
    independent: bool = False,
) -> Dict[str, Any]:
    rows = list(finding.get("evidence") or [])
    rows.append(evidence)
    finding = dict(finding)
    finding["evidence"] = rows
    independent_count = sum(1 for row in rows if row.get("independent"))
    if independent:
        evidence = dict(evidence)
        evidence["independent"] = True
        rows[-1] = evidence
        finding["evidence"] = rows
        independent_count += 1
    state = promote_evidence(
        finding.get("evidence_state", "probable"),
        independent_sources=independent_count,
    )
    finding["evidence_state"] = state
    finding["confidence"] = finding_confidence_from_evidence(rows)
    return finding
