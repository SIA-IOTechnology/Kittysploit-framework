#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Build normalized ``ModuleResult`` values from HTTP scanner hits."""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

HitMapper = Callable[[Dict[str, Any]], Dict[str, Any]]


def _option_value(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "value"):
        return value.value
    return value


def target_base_url(module: Any, *, path: str = "/") -> str:
    """Best-effort base URL for the active HTTP scanner module."""
    try:
        target = _option_value(getattr(module, "target", None) or getattr(module, "rhost", None))
        if not target:
            return ""
        port = _option_value(getattr(module, "port", None))
        port = int(port) if port not in (None, "") else (443 if _option_value(getattr(module, "ssl", False)) else 80)
        protocol = "https"
        if hasattr(module, "ssl"):
            protocol = "https" if bool(_option_value(module.ssl)) else "http"
        elif port != 443:
            protocol = "http"
        suffix = path if str(path).startswith("/") else f"/{path}"
        return f"{protocol}://{target}:{port}{suffix}"
    except Exception:
        return ""


def http_hit_to_evidence_dict(
    hit: Dict[str, Any],
    *,
    module: Any = None,
    title: str = "",
) -> Dict[str, Any]:
    """Map a scanner hit to a legacy HTTP evidence payload for normalization."""
    request_url = (
        str(hit.get("request_url") or hit.get("url") or hit.get("endpoint") or "").strip()
    )
    if not request_url and module is not None:
        request_url = target_base_url(module, path=str(hit.get("path") or "/"))

    snippet = (
        hit.get("evidence_snippet")
        or hit.get("content_preview")
        or hit.get("match")
        or hit.get("indicator")
        or ", ".join(hit.get("indicators") or [])
        or ", ".join(hit.get("details") or [])
    )
    if not snippet and hit.get("origin"):
        snippet = f"origin={hit.get('origin')}"
        if hit.get("vulnerability_type"):
            snippet = f"{hit.get('vulnerability_type')}: {snippet}"

    evidence_title = (
        title
        or hit.get("vulnerability_type")
        or hit.get("injection_type")
        or hit.get("xss_type")
        or hit.get("ssrf_type")
        or hit.get("xxe_type")
        or hit.get("type")
        or "HTTP scanner hit"
    )

    payload: Dict[str, Any] = {
        "kind": "http",
        "title": str(evidence_title)[:256],
        "method": str(hit.get("method") or "GET").upper(),
        "request_url": request_url,
        "status_code": hit.get("status_code"),
        "evidence_snippet": str(snippet or "")[:2000],
    }
    if hit.get("payload"):
        payload["metadata"] = {"payload": str(hit.get("payload"))[:500]}
    if hit.get("param"):
        metadata = dict(payload.get("metadata") or {})
        metadata["param"] = str(hit.get("param"))
        payload["metadata"] = metadata
    return payload


def select_hits(
    hits: Sequence[Dict[str, Any]],
    *,
    dedupe_keys: Optional[Sequence[str]] = None,
    max_hits: int = 24,
    hit_mapper: Optional[HitMapper] = None,
    only_vulnerable: bool = False,
) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    seen: set[Tuple[Any, ...]] = set()
    for raw in hits or []:
        if not isinstance(raw, dict):
            continue
        if only_vulnerable and not raw.get("vulnerable", True):
            continue
        item = hit_mapper(raw) if hit_mapper else dict(raw)
        if dedupe_keys:
            key = tuple(item.get(field) for field in dedupe_keys)
            if key in seen:
                continue
            seen.add(key)
        selected.append(item)
        if len(selected) >= max_hits:
            break
    return selected


def finalize_http_scanner_run(
    module: Any,
    hits: Sequence[Dict[str, Any]],
    *,
    title: str,
    severity: str = "medium",
    reason: str = "",
    category: str = "web",
    findings_key: str = "hits",
    dedupe_keys: Optional[Sequence[str]] = None,
    max_hits: int = 24,
    hit_mapper: Optional[HitMapper] = None,
    only_vulnerable: bool = False,
    vulnerability_info_extra: Optional[Dict[str, Any]] = None,
) -> Any:
    """Return a ``ModuleResult`` with finding/evidence when hits exist."""
    module_result = getattr(module, "module_result", None)
    if module_result is None:
        from core.framework.base_module import ModuleResult

        def module_result(**kwargs: Any) -> ModuleResult:
            return ModuleResult(**kwargs)

    hits_out = select_hits(
        hits,
        dedupe_keys=dedupe_keys,
        max_hits=max_hits,
        hit_mapper=hit_mapper,
        only_vulnerable=only_vulnerable,
    )
    if not hits_out:
        if hasattr(module, "vulnerability_info"):
            module.vulnerability_info = {}
        return module_result(success=True)

    summary_reason = reason.strip()
    if not summary_reason:
        first = hits_out[0]
        lead = (
            first.get("vulnerability_type")
            or first.get("injection_type")
            or first.get("type")
            or first.get("path")
            or first.get("param")
            or title
        )
        summary_reason = f"Potential {title}: {lead}"
        if len(hits_out) > 1:
            summary_reason = f"{summary_reason} (+{len(hits_out) - 1} more)"

    if hasattr(module, "vulnerability_info"):
        module.vulnerability_info = {
            "reason": summary_reason,
            "severity": severity,
            findings_key: hits_out,
            f"{findings_key}_count": len(hits if isinstance(hits, (list, tuple)) else list(hits or [])),
            **(vulnerability_info_extra or {}),
        }

    evidence = [
        http_hit_to_evidence_dict(hit, module=module, title=title)
        for hit in hits_out
    ]
    return module_result(
        success=True,
        finding={
            "title": title,
            "severity": severity,
            "reason": summary_reason,
            "description": summary_reason,
            "category": category,
            "status": "affected",
        },
        evidence=evidence,
    )
