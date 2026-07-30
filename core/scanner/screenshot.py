#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Headless page screenshots for scanner evidence (Playwright, optional)."""

from __future__ import annotations

import base64
import os
import re
import threading
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

_LOCK = threading.Lock()
_PLAYWRIGHT_WARNED = False


def playwright_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401

        return True
    except Exception:
        return False


def resolve_screenshot_url(result: Dict[str, Any], target_info: Optional[Dict[str, Any]] = None) -> str:
    """Best-effort absolute URL for a vulnerable scanner hit."""
    report = result.get("report") if isinstance(result.get("report"), dict) else {}
    evidence = result.get("report_evidence") if isinstance(result.get("report_evidence"), dict) else {}
    if not evidence and isinstance(report.get("evidence"), dict):
        evidence = report["evidence"]

    for key in ("url", "request_url"):
        value = str((evidence or {}).get(key) or "").strip()
        if value.startswith("http://") or value.startswith("https://"):
            return value

    details = result.get("details") if isinstance(result.get("details"), dict) else {}
    for key in ("url", "path"):
        value = str(details.get(key) or result.get(key) or "").strip()
        if value.startswith("http://") or value.startswith("https://"):
            return value

    host = str(result.get("host") or (target_info or {}).get("hostname") or "").strip()
    if not host:
        return ""
    scheme = str(result.get("scheme") or (target_info or {}).get("scheme") or "http").strip() or "http"
    port = result.get("port")
    if port in (None, ""):
        port = (target_info or {}).get("port")
    try:
        port_i = int(port) if port not in (None, "") else (443 if scheme == "https" else 80)
    except (TypeError, ValueError):
        port_i = 443 if scheme == "https" else 80

    path = ""
    for candidate in (
        (evidence or {}).get("path"),
        details.get("path"),
        result.get("http_path"),
    ):
        text = str(candidate or "").strip()
        if text:
            path = text if text.startswith("/") else f"/{text}"
            break
    if not path:
        path = "/"

    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/") + path
    return f"{scheme}://{host}:{port_i}{path}"


def capture_page_screenshot(
    url: str,
    *,
    output_dir: str,
    filename: Optional[str] = None,
    timeout_ms: int = 15000,
    full_page: bool = False,
    viewport: Optional[Dict[str, int]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Capture a PNG screenshot of ``url``.

    Returns dict with ``path``, ``relative_path``, ``filename``, ``sha256``, ``bytes``
    or ``None`` when Playwright is missing / capture fails.
    """
    global _PLAYWRIGHT_WARNED
    target = str(url or "").strip()
    if not target.startswith(("http://", "https://")):
        return None

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        if not _PLAYWRIGHT_WARNED:
            _PLAYWRIGHT_WARNED = True
        return None

    os.makedirs(output_dir, exist_ok=True)
    name = filename or f"screenshot_{uuid.uuid4().hex[:10]}.png"
    if not name.lower().endswith(".png"):
        name += ".png"
    abs_path = os.path.join(output_dir, name)

    with _LOCK:
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    context = browser.new_context(
                        viewport=viewport or {"width": 1280, "height": 720},
                        ignore_https_errors=True,
                    )
                    page = context.new_page()
                    page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
                    try:
                        page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 5000))
                    except Exception:
                        pass
                    page.screenshot(path=abs_path, full_page=bool(full_page))
                    context.close()
                finally:
                    browser.close()
        except Exception:
            return None

    if not os.path.isfile(abs_path):
        return None

    data = b""
    try:
        with open(abs_path, "rb") as handle:
            data = handle.read()
    except Exception:
        data = b""

    import hashlib

    digest = hashlib.sha256(data).hexdigest() if data else None
    try:
        rel = os.path.relpath(abs_path, os.getcwd())
    except ValueError:
        rel = abs_path

    return {
        "path": abs_path,
        "relative_path": rel,
        "filename": name,
        "sha256": digest,
        "bytes": len(data),
        "url": target,
        "content_type": "image/png",
    }


def attach_screenshots_to_results(
    results: Sequence[Dict[str, Any]],
    *,
    evidence_dir: str,
    target_info: Optional[Dict[str, Any]] = None,
    timeout_ms: int = 15000,
) -> Tuple[int, Optional[str]]:
    """
    Capture screenshots for vulnerable HTTP hits.

    Mutates matching result dicts (report.evidence.screenshot, evidence_paths, …).
    Returns ``(count, warning_message)``.
    """
    if not playwright_available():
        return 0, (
            "Screenshots skipped: Playwright is not installed. "
            "Install with: pip install playwright && playwright install chromium"
        )

    captured = 0
    for index, result in enumerate(results):
        if not isinstance(result, dict) or not result.get("vulnerable"):
            continue
        url = resolve_screenshot_url(result, target_info)
        if not url:
            continue
        # Skip if module already provided a screenshot path that exists
        report = result.get("report") if isinstance(result.get("report"), dict) else {}
        evidence = {}
        if isinstance(result.get("report_evidence"), dict):
            evidence = dict(result["report_evidence"])
        elif isinstance(report.get("evidence"), dict):
            evidence = dict(report["evidence"])
        existing = str(evidence.get("screenshot") or "").strip()
        if existing and os.path.isfile(existing):
            continue

        slug = _safe_slug(
            str(result.get("finding") or result.get("module") or result.get("path") or "finding")
        )[:40]
        shot = capture_page_screenshot(
            url,
            output_dir=evidence_dir,
            filename=f"{index:03d}_{slug}.png",
            timeout_ms=timeout_ms,
        )
        if not shot:
            continue

        rel = shot["relative_path"]
        evidence["screenshot"] = rel
        evidence.setdefault("url", url)
        result["report_evidence"] = evidence
        result["screenshot"] = rel
        result["screenshot_sha256"] = shot.get("sha256")

        if isinstance(report, dict) and report:
            report = dict(report)
            report_evidence = dict(report.get("evidence") or {})
            report_evidence.update(evidence)
            report["evidence"] = report_evidence
            result["report"] = report
        else:
            # Minimal report so KittyReport push keeps the screenshot
            finding = str(result.get("finding") or result.get("message") or result.get("module") or "Finding")
            result["report"] = {
                "finding": finding,
                "severity": str(result.get("severity") or "info").lower(),
                "evidence": evidence,
            }
            result["finding"] = finding

        paths = list(result.get("evidence_paths") or [])
        if rel not in paths:
            paths.append(rel)
        result["evidence_paths"] = paths

        # Refresh short table preview
        preview = str(result.get("evidence") or "")
        tag = f"screenshot={os.path.basename(rel)}"
        if tag not in preview:
            result["evidence"] = f"{preview} | {tag}".strip(" |") if preview else tag

        # Append screenshot artifact onto schema evidence metadata when present
        schema = list(result.get("schema_evidence") or [])
        if schema and isinstance(schema[0], dict):
            first = dict(schema[0])
            meta = dict(first.get("metadata") or {})
            meta["screenshot"] = rel
            if shot.get("sha256"):
                meta["screenshot_sha256"] = shot["sha256"]
            first["metadata"] = meta
            artifact = {
                "path": rel,
                "content_type": "image/png",
                "sha256": shot.get("sha256"),
            }
            first["artifact"] = artifact
            # Prefer keeping http kind but also note screenshot file
            if not first.get("kind"):
                first["kind"] = "screenshot"
            schema[0] = first
            result["schema_evidence"] = schema
        else:
            result["schema_evidence"] = [
                {
                    "kind": "screenshot",
                    "summary": f"Screenshot of {url}",
                    "path": rel,
                    "artifact": {
                        "path": rel,
                        "content_type": "image/png",
                        "sha256": shot.get("sha256"),
                    },
                    "metadata": {"screenshot": rel, "url": url},
                }
            ]

        # Rewrite JSON evidence sidecar if we already wrote one
        _update_evidence_json_files(result, evidence_dir)
        captured += 1

    return captured, None


def screenshot_to_data_url(path: str, *, max_bytes: int = 1_500_000) -> Optional[str]:
    """Embed a small PNG as data URL for KittyReport push (skip if too large)."""
    abs_path = path
    if not os.path.isabs(abs_path):
        abs_path = os.path.join(os.getcwd(), path)
    try:
        size = os.path.getsize(abs_path)
        if size <= 0 or size > max_bytes:
            return None
        with open(abs_path, "rb") as handle:
            raw = handle.read()
        b64 = base64.b64encode(raw).decode("ascii")
        return f"data:image/png;base64,{b64}"
    except Exception:
        return None


def enrich_kittyreport_evidence_with_screenshot(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Add ``screenshot_data_url`` when a local screenshot file is referenced."""
    if not isinstance(evidence, dict):
        return {}
    out = dict(evidence)
    path = str(out.get("screenshot") or "").strip()
    if not path:
        return out
    data_url = screenshot_to_data_url(path)
    if data_url:
        out["screenshot_data_url"] = data_url
    return out


def _update_evidence_json_files(result: Dict[str, Any], evidence_dir: str) -> None:
    paths = [
        str(p)
        for p in (result.get("evidence_paths") or [])
        if str(p).lower().endswith(".json")
    ]
    if not paths:
        return
    payload = result.get("schema_evidence") or result.get("report")
    if not payload:
        return
    import json

    for path in paths:
        abs_path = path if os.path.isabs(path) else os.path.join(os.getcwd(), path)
        if not abs_path.startswith(os.path.abspath(evidence_dir)):
            # Still allow rewriting known evidence JSON files
            pass
        try:
            with open(abs_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
        except Exception:
            continue


def _safe_slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    return text.strip("._") or "item"
