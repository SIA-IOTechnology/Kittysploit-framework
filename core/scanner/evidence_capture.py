#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Capture structured scanner evidence (HTTP exchanges, artifacts) for KittyReport."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

MAX_BODY_CHARS = 8000

_SENSITIVE_HEADER_MARKERS = (
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
)


def new_scan_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{uuid.uuid4().hex[:8]}"


def evidence_dir_for_scan(
    *,
    workspace: str = "default",
    scan_id: Optional[str] = None,
    base_dir: Optional[str] = None,
) -> Tuple[str, str]:
    """Return ``(scan_id, absolute_dir)`` under ``output/evidence/<workspace>/<scan_id>``."""
    sid = scan_id or new_scan_id()
    root = base_dir or os.path.join(os.getcwd(), "output", "evidence")
    path = os.path.join(root, _safe_slug(workspace or "default"), sid)
    os.makedirs(path, exist_ok=True)
    return sid, path


def capture_last_http_exchange(module: Any) -> Optional[Dict[str, Any]]:
    """Build a legacy evidence dict from ``Http_client`` last-response tracking."""
    response = getattr(module, "_ks_last_http_response", None)
    if response is None:
        return None

    method = str(getattr(module, "_ks_last_http_method", "") or "").strip().upper()
    path = str(getattr(module, "_ks_last_http_path", "") or "").strip() or "/"

    request_url = ""
    request_headers: Dict[str, str] = {}
    request_body = None
    try:
        req = getattr(response, "request", None)
        if req is not None:
            request_url = str(getattr(req, "url", "") or "").strip()
            method = str(getattr(req, "method", None) or method or "GET").upper()
            request_headers = _headers_to_dict(getattr(req, "headers", None))
            body = getattr(req, "body", None)
            if body is not None:
                if isinstance(body, bytes):
                    request_body = body.decode("utf-8", errors="replace")
                else:
                    request_body = str(body)
    except Exception:
        pass

    if not request_url:
        request_url = str(getattr(response, "url", "") or "").strip()
    if not request_url:
        request_url = _guess_url_from_module(module, path)

    status_code = None
    try:
        status_code = int(getattr(response, "status_code", None))
    except (TypeError, ValueError):
        status_code = None

    response_headers = _headers_to_dict(getattr(response, "headers", None))
    try:
        body_text = str(getattr(response, "text", "") or "")
    except Exception:
        body_text = ""
    body_text = body_text[:MAX_BODY_CHARS]
    body_sha = hashlib.sha256(body_text.encode("utf-8", errors="replace")).hexdigest() if body_text else None

    elapsed_ms = None
    try:
        elapsed = getattr(response, "elapsed", None)
        if elapsed is not None:
            elapsed_ms = float(elapsed.total_seconds()) * 1000.0
    except Exception:
        elapsed_ms = None

    legacy: Dict[str, Any] = {
        "kind": "http",
        "method": method or "GET",
        "request_url": request_url,
        "url": request_url,
        "request_headers": _redact_headers(request_headers),
        "status_code": status_code,
        "response_headers": _redact_headers(response_headers),
        "response_body": body_text,
        "evidence_snippet": body_text[:400] if body_text else None,
        "body_sha256": body_sha,
    }
    if request_body is not None:
        legacy["request_body"] = str(request_body)[:MAX_BODY_CHARS]
    if elapsed_ms is not None:
        legacy["elapsed_ms"] = elapsed_ms
    return legacy


def has_http_payload(records: Sequence[Dict[str, Any]]) -> bool:
    for record in records or []:
        if not isinstance(record, dict):
            continue
        kind = str(record.get("kind") or record.get("type") or "").lower()
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        if kind == "http" and (response.get("body_text") or response.get("status_code") or request.get("url")):
            return True
    return False


def collect_module_evidence(
    *,
    module: Any,
    module_path: str,
    result: Dict[str, Any],
    workspace: Optional[str] = None,
    existing_schema: Optional[Sequence[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Return schema Evidence records for a vulnerable scanner hit."""
    records: List[Dict[str, Any]] = [
        dict(item) for item in (existing_schema or []) if isinstance(item, dict)
    ]

    # Prefer structured report_finding() evidence when present.
    report_evidence = result.get("report_evidence")
    if not isinstance(report_evidence, dict):
        report = result.get("report") if isinstance(result.get("report"), dict) else {}
        if isinstance(report.get("evidence"), dict):
            report_evidence = report["evidence"]

    if isinstance(report_evidence, dict) and report_evidence:
        legacy = {
            "kind": "http" if (report_evidence.get("url") or report_evidence.get("status_code")) else "note",
            "request_url": report_evidence.get("url") or report_evidence.get("request_url"),
            "url": report_evidence.get("url") or report_evidence.get("request_url"),
            "method": report_evidence.get("method") or "GET",
            "status_code": report_evidence.get("status_code"),
            "evidence_snippet": report_evidence.get("snippet")
            or report_evidence.get("summary")
            or json.dumps(report_evidence, ensure_ascii=False, default=str)[:400],
            "response_body": report_evidence.get("body")
            or report_evidence.get("response_body")
            or report_evidence.get("snippet"),
            "summary": str(result.get("finding") or result.get("message") or "")[:4000] or None,
            "metadata": {
                k: v
                for k, v in report_evidence.items()
                if k
                not in (
                    "url",
                    "request_url",
                    "method",
                    "status_code",
                    "snippet",
                    "summary",
                    "body",
                    "response_body",
                )
            },
        }
        built = _legacy_to_schema(
            legacy,
            module=module,
            module_path=module_path,
            workspace=workspace,
            finding=result,
        )
        if built:
            records = built

    if not has_http_payload(records):
        legacy = capture_last_http_exchange(module)
        if legacy:
            built = _legacy_to_schema(
                legacy,
                module=module,
                module_path=module_path,
                workspace=workspace,
                finding=result,
            )
            if built:
                records = built

    if not records:
        summary = str(result.get("message") or result.get("evidence") or "").strip()
        if not summary:
            summary = f"Finding confirmed by {module_path or 'scanner'}"
        note = {
            "kind": "note",
            "summary": summary[:4000],
            "content_preview": summary[:240],
            "evidence_snippet": summary[:400],
        }
        built = _legacy_to_schema(
            note,
            module=module,
            module_path=module_path,
            workspace=workspace,
            finding=result,
        )
        if built:
            records = built

    return records


def write_evidence_records(
    records: Sequence[Dict[str, Any]],
    *,
    directory: str,
    module_path: str = "",
    index: Optional[int] = None,
) -> List[str]:
    """Persist evidence JSON files; return relative paths from cwd when possible."""
    if not records:
        return []
    os.makedirs(directory, exist_ok=True)
    slug = _safe_slug(module_path.split("/")[-1] if module_path else "finding")[:40] or "finding"
    prefix = f"{int(index):03d}_" if index is not None else ""
    filename = f"{prefix}{slug}_{uuid.uuid4().hex[:8]}.json"
    abs_path = os.path.join(directory, filename)
    payload = list(records)
    with open(abs_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)

    try:
        return [os.path.relpath(abs_path, os.getcwd())]
    except ValueError:
        return [abs_path]


def evidence_preview(records: Sequence[Dict[str, Any]], limit: int = 400) -> str:
    """Short human-readable preview for tables / PoC text."""
    parts: List[str] = []
    for record in records or []:
        if not isinstance(record, dict):
            continue
        summary = str(record.get("summary") or record.get("content_preview") or "").strip()
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        if request.get("method") or request.get("url"):
            line = f"{request.get('method') or 'GET'} {request.get('url') or ''}".strip()
            if response.get("status_code") is not None:
                line = f"{line} -> {response.get('status_code')}"
            parts.append(line)
        elif summary:
            parts.append(summary)
        body = str(response.get("body_text") or "").strip()
        if body and len(parts) < 2:
            parts.append(body[:160].replace("\n", " "))
        if parts:
            break
    text = " | ".join(parts).strip()
    return text[:limit]


def _legacy_to_schema(
    legacy: Dict[str, Any],
    *,
    module: Any,
    module_path: str,
    workspace: Optional[str],
    finding: Any,
) -> List[Dict[str, Any]]:
    try:
        from core.framework.base_module import ModuleResult
        from core.framework.evidence_adapter import module_result_to_evidence

        return module_result_to_evidence(
            ModuleResult(success=True, evidence=legacy, finding=finding),
            module=module,
            module_path=module_path,
            workspace=workspace,
            finding=finding,
        )
    except Exception:
        return []


def _headers_to_dict(headers: Any) -> Dict[str, str]:
    if headers is None:
        return {}
    try:
        return {str(k): str(v) for k, v in dict(headers).items()}
    except Exception:
        return {}


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    redacted: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        low = str(key).lower()
        if any(marker in low for marker in _SENSITIVE_HEADER_MARKERS):
            redacted[str(key)] = "[redacted]"
        else:
            redacted[str(key)] = str(value)[:2000]
    return redacted


def _guess_url_from_module(module: Any, path: str) -> str:
    host = ""
    for attr in ("target", "rhost", "rhosts", "host"):
        raw = getattr(module, attr, None)
        if raw is None:
            continue
        value = getattr(raw, "value", raw)
        text = str(value or "").strip()
        if text and text.lower() != "none":
            host = text
            break
    if not host:
        return path or "/"
    port = getattr(module, "port", None) or getattr(module, "rport", None)
    port_v = getattr(port, "value", port) if port is not None else None
    ssl = getattr(module, "ssl", None)
    ssl_v = getattr(ssl, "value", ssl) if ssl is not None else None
    scheme = "https" if ssl_v in (True, "true", "True", 1, "1") else "http"
    try:
        port_i = int(port_v) if port_v not in (None, "") else (443 if scheme == "https" else 80)
    except (TypeError, ValueError):
        port_i = 443 if scheme == "https" else 80
    path_s = path if str(path).startswith("/") else f"/{path}"
    return f"{scheme}://{host}:{port_i}{path_s}"


def _safe_slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    return text.strip("._") or "item"
