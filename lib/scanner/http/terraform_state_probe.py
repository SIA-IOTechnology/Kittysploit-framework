#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Terraform state file exposure and secret extraction."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

_STATE_PATHS = (
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/tf/terraform.tfstate",
    "/infra/terraform.tfstate",
    "/.terraform/terraform.tfstate",
    "/state/terraform.tfstate",
    "/state/default.tfstate",
    "/backend.tfstate",
    "/prod/terraform.tfstate",
    "/staging/terraform.tfstate",
    "/dev/terraform.tfstate",
)

_SENSITIVE_KEYS = (
    "password",
    "secret",
    "private_key",
    "access_key",
    "api_key",
    "token",
    "connection_string",
    "client_secret",
    "aws_secret",
)

_SECRET_VALUE_RE = re.compile(
    r"(?i)(password|secret|private_key|access_key|api_key|token|connection_string)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
)


def _walk_sensitive(obj: Any, prefix: str = "", found: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, str]]:
    out = found if found is not None else []
    if isinstance(obj, dict):
        for key, val in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            key_l = str(key).lower()
            if any(s in key_l for s in _SENSITIVE_KEYS) and isinstance(val, (str, int)):
                val_s = str(val)
                if len(val_s) >= 8 and val_s not in ("changeme", "placeholder", "example"):
                    out.append(
                        {
                            "path": path,
                            "key": str(key),
                            "value_masked": val_s[:3] + "…" + val_s[-3:] if len(val_s) > 10 else "…",
                            "severity": "critical" if "private_key" in key_l or "secret" in key_l else "high",
                        }
                    )
            _walk_sensitive(val, path, out)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj[:50]):
            _walk_sensitive(item, f"{prefix}[{idx}]", out)
    return out


def parse_tfstate_secrets(text: str) -> List[Dict[str, str]]:
    secrets: List[Dict[str, str]] = []
    body = text or ""
    try:
        data = json.loads(body)
        secrets.extend(_walk_sensitive(data)[:25])
    except Exception:
        pass
    for match in _SECRET_VALUE_RE.finditer(body):
        secrets.append(
            {
                "path": match.group(1),
                "key": match.group(1),
                "value_masked": match.group(2)[:3] + "…",
                "severity": "high",
            }
        )
    return secrets[:25]


def scan_terraform_state(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in _STATE_PATHS:
        response = http_request(method="GET", path=path, allow_redirects=False, timeout=12)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        body = str(getattr(response, "text", "") or "")
        if not body.strip().startswith("{"):
            continue
        if "terraform_version" not in body and "resources" not in body and "outputs" not in body:
            continue
        secrets = parse_tfstate_secrets(body)
        severity = "critical" if secrets else "high"
        findings.append(
            {
                "path": path,
                "kind": "terraform_state_exposed",
                "secrets": secrets,
                "secret_count": len(secrets),
                "preview": body[:400],
                "severity": severity,
            }
        )
    return findings


__all__ = ["parse_tfstate_secrets", "scan_terraform_state"]
