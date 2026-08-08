#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed GitHub Actions workflow files and CI secret patterns."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

_WORKFLOW_PATHS = (
    "/.github/workflows/main.yml",
    "/.github/workflows/ci.yml",
    "/.github/workflows/build.yml",
    "/.github/workflows/deploy.yml",
    "/.github/workflows/release.yml",
    "/.github/workflows/test.yml",
    "/.github/workflows/docker.yml",
    "/.github/workflows/publish.yml",
)

_SECRET_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    (r"(?i)\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}", "github_actions_secret_ref", "critical"),
    (r"(?i)secrets\.([A-Z0-9_]+)", "github_actions_secret_name", "high"),
    (r"(?i)(?:password|passwd|token|api[_-]?key|secret|private[_-]?key)\s*:\s*['\"]?([^\s'\"#]{8,})['\"]?", "inline_secret", "critical"),
    (r"\bghp_[A-Za-z0-9]{20,}\b", "github_pat", "critical"),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "github_fine_pat", "critical"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key", "high"),
    (r"(?i)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private_key_pem", "critical"),
    (r"(?i)DOCKER_(?:PASSWORD|TOKEN|HUB_TOKEN)\s*[:=]\s*['\"]?[^\s'\"#]+", "docker_secret", "high"),
)

_COMPILED = [(re.compile(rx), kind, sev) for rx, kind, sev in _SECRET_PATTERNS]


def scan_workflow_text(path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    sample = text or ""
    if not sample.strip():
        return findings
    for regex, kind, severity in _COMPILED:
        for match in regex.finditer(sample):
            key = (path, kind, match.group(0)[:80])
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "path": path,
                    "kind": kind,
                    "severity": severity,
                    "match": match.group(0)[:200],
                    "line_hint": sample[: match.start()].count("\n") + 1,
                }
            )
    return findings


def collect_workflow_bodies(
    http_request: Callable[..., Any],
) -> List[Tuple[str, str]]:
    bodies: List[Tuple[str, str]] = []
    for path in _WORKFLOW_PATHS:
        response = http_request(method="GET", path=path, allow_redirects=False)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        text = str(getattr(response, "text", "") or "")
        lowered = text.lower()
        if "runs-on:" in lowered or "steps:" in lowered or "on:" in lowered:
            bodies.append((path, text))
    return bodies


def extract_github_workflow_findings(
    http_request: Callable[..., Any],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path, text in collect_workflow_bodies(http_request):
        out.extend(scan_workflow_text(path, text))
    return out


__all__ = [
    "collect_workflow_bodies",
    "extract_github_workflow_findings",
    "scan_workflow_text",
]
