#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitLab CI/CD YAML exposure and secret pattern extraction."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

_CI_PATHS = (
    "/.gitlab-ci.yml",
    "/gitlab-ci.yml",
    "/.gitlab-ci/variables.yml",
    "/.gitlab/ci/deploy.yml",
    "/.gitlab/ci/build.yml",
    "/.gitlab/ci/test.yml",
    "/.gitlab/ci/security.yml",
    "/ci/.gitlab-ci.yml",
)

_SECRET_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    (r"(?i)\b(AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY))\s*[:=]\s*['\"]?([^\s'\"#]+)", "aws", "critical"),
    (r"(?i)\b(DOCKER_(?:PASSWORD|TOKEN|AUTH))\s*[:=]\s*['\"]?([^\s'\"#]+)", "docker", "high"),
    (r"(?i)\b(CI_(?:JOB_TOKEN|DEPLOY_TOKEN|REGISTRY_PASSWORD))\s*[:=]\s*['\"]?([^\s'\"#]+)", "gitlab", "critical"),
    (r"(?i)\b(KUBECONFIG|KUBE_(?:TOKEN|CONFIG))\s*[:=]\s*['\"]?([^\s'\"#]+)", "kubernetes", "high"),
    (r"(?i)\b(SSH_(?:PRIVATE_KEY|KEY))\s*[:=]\s*['\"]?([^\s'\"#]+)", "ssh", "critical"),
    (r"(?i)\b(DATABASE_URL|DB_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*[:=]\s*['\"]?([^\s'\"#]+)", "database", "critical"),
    (r"(?i)\$\{?([A-Z0-9_]{3,40})\}?", "variable_ref", "info"),
    (r"(?i)\b(ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,})\b", "token", "critical"),
    (r"(?i)\b(AKIA[0-9A-Z]{16})\b", "aws", "high"),
)

_CI_MARKERS = ("variables:", "before_script:", "script:", "stage:", "image:")


def _looks_like_gitlab_ci(text: str) -> bool:
    body = text or ""
    hits = sum(1 for m in _CI_MARKERS if m in body)
    return hits >= 3


def extract_ci_secrets(text: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()
    for pattern, category, severity in _SECRET_PATTERNS:
        for match in re.finditer(pattern, text or ""):
            if category == "variable_ref":
                name = match.group(1)
                if name in ("CI", "CI_JOB_NAME", "CI_COMMIT_SHA", "CI_PROJECT_DIR"):
                    continue
                key = f"var:{name}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append({"kind": "ci_variable_ref", "name": name, "severity": "info"})
                continue
            var_name = match.group(1) if match.lastindex and match.lastindex >= 1 else category
            value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
            key = f"{var_name}:{value[:20]}"
            if key in seen:
                continue
            seen.add(key)
            masked = value[:4] + "…" + value[-4:] if len(value) > 12 else "…"
            findings.append(
                {
                    "kind": "embedded_secret",
                    "category": category,
                    "name": str(var_name),
                    "value_masked": masked,
                    "severity": severity,
                }
            )
    return findings


def scan_gitlab_ci(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in _CI_PATHS:
        response = http_request(method="GET", path=path, allow_redirects=False, timeout=10)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        body = str(getattr(response, "text", "") or "")
        if not _looks_like_gitlab_ci(body):
            continue
        secrets = extract_ci_secrets(body)
        severity = "critical" if any(s.get("severity") == "critical" for s in secrets) else "medium"
        findings.append(
            {
                "path": path,
                "kind": "gitlab_ci_exposed",
                "secrets": secrets[:20],
                "secret_count": len(secrets),
                "preview": body[:600],
                "severity": severity,
            }
        )
    return findings


__all__ = ["extract_ci_secrets", "scan_gitlab_ci"]
