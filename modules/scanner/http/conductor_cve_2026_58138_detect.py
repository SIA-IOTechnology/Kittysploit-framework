#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Orkes Conductor / Conductor OSS instances vulnerable to CVE-2026-58138."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client

CONDUCTOR_VULN_MIN = "3.21.21"
CONDUCTOR_PATCHED = "3.30.2"


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Orkes Conductor CVE-2026-58138 (unauthenticated RCE) detection",
        "description": (
            "Detects Conductor OSS / Orkes Conductor instances running a version below 3.30.2 "
            "that may be vulnerable to CVE-2026-58138 (unauthenticated INLINE JavaScript RCE)."
        ),
        "author": ["Mohammed Idrees Banyamer", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-58138",
        "references": [
            "https://github.com/conductor-oss/conductor",
            "https://www.cve.org/CVERecord?id=CVE-2026-58138",
        ],
        "modules": [
            "exploits/multi/http/conductor_cve_2026_58138_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "conductor",
            "orkes",
            "netflix",
            "rce",
            "cve-2026-58138",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["conductor"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/api/metadata/workflow"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "rce", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(8080, "Conductor API port", required=True)
    ssl = OptBool(False, "Use HTTPS", required=True)
    path = OptString("/", "Base path where Conductor API is exposed", required=False)

    @staticmethod
    def _parse_version(version: str) -> tuple[int, ...]:
        parts: list[int] = []
        for token in str(version or "").strip().split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)

    @classmethod
    def _version_lt(cls, left: str, right: str) -> bool:
        a = cls._parse_version(left)
        b = cls._parse_version(right)
        length = max(len(a), len(b))
        for index in range(length):
            av = a[index] if index < len(a) else 0
            bv = b[index] if index < len(b) else 0
            if av < bv:
                return True
            if av > bv:
                return False
        return False

    @classmethod
    def _version_gte(cls, left: str, right: str) -> bool:
        return not cls._version_lt(left, right)

    @classmethod
    def _version_in_vuln_range(cls, version: str) -> bool:
        if not version:
            return False
        return (
            cls._version_gte(version, CONDUCTOR_VULN_MIN)
            and cls._version_lt(version, CONDUCTOR_PATCHED)
        )

    def _api_path(self, suffix: str) -> str:
        base = str(self.path or "/").strip() or "/"
        if not base.startswith("/"):
            base = f"/{base}"
        if base.endswith("/"):
            base = base[:-1]
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return suffix if base == "" else f"{base}{suffix}"

    @staticmethod
    def _extract_version_from_body(body: str) -> Optional[str]:
        if not body:
            return None
        try:
            payload = json.loads(body)
        except Exception:
            payload = None

        if isinstance(payload, dict):
            for key in ("version", "buildVersion", "conductorVersion", "appVersion"):
                value = payload.get(key)
                if value:
                    return str(value).strip()
            for bucket in ("config", "build", "serverConfig", "system"):
                nested = payload.get(bucket)
                if isinstance(nested, dict):
                    for key in ("version", "buildVersion", "conductorVersion"):
                        value = nested.get(key)
                        if value:
                            return str(value).strip()

        match = re.search(
            r'"(?:version|buildVersion|conductorVersion)"\s*:\s*"([0-9]+(?:\.[0-9]+)*)"',
            body,
            re.IGNORECASE,
        )
        return match.group(1) if match else None

    def _probe_conductor(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"found": False, "version": None, "evidence": None}
        for probe_path in ("/api/admin/config", "/api/sys", "/api/metadata/workflow"):
            response = self.http_request(
                method="GET",
                path=self._api_path(probe_path),
                headers={"Accept": "application/json,text/plain,*/*"},
                allow_redirects=True,
                timeout=15,
            )
            if not response:
                continue
            body = response.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
            if response.status_code not in (200, 401, 403, 405):
                continue
            if "conductor" not in body.lower() and "conductor" not in headers:
                if probe_path != "/api/metadata/workflow":
                    continue
            version = self._extract_version_from_body(body)
            result.update({"found": True, "version": version, "evidence": probe_path})
            if version:
                return result
        return result

    def run(self):
        try:
            probe = self._probe_conductor()
            if not probe.get("found"):
                return False

            version = probe.get("version")
            evidence = probe.get("evidence")

            if version and not self._version_in_vuln_range(version):
                if self._version_gte(version, CONDUCTOR_PATCHED):
                    print_status(f"Conductor {version} >= {CONDUCTOR_PATCHED} (patched)")
                return False

            if version and self._version_in_vuln_range(version):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-58138",
                    reason=(
                        f"Conductor {version} detected via {evidence}; "
                        f"affected range [{CONDUCTOR_VULN_MIN}, {CONDUCTOR_PATCHED})."
                    ),
                    conductor_version=version,
                    evidence_path=evidence,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="high",
                cve="CVE-2026-58138",
                reason=(
                    "Conductor API detected but version unknown; "
                    f"may be vulnerable if < {CONDUCTOR_PATCHED}."
                ),
                conductor_version=version or "unknown",
                evidence_path=evidence,
                confidence="medium",
            )
            return True

        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
