#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response

_AFFECTED_MIN = "0.8.2"
_FIXED_VERSION = "0.11.1"


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Zeppelin CVE-2024-31866 detection",
        "description": (
            "Fingerprints Apache Zeppelin via /api/version and flags versions "
            f">= {_AFFECTED_MIN} and < {_FIXED_VERSION} potentially affected by "
            "CVE-2024-31866 (interpreter classpath env injection). "
            "Version check only — no exploitation."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2024-31866",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-31866",
            "https://lists.apache.org/thread/jpkbq3oktopt34x2n5wnhzc2r1410ddd",
            "https://github.com/apache/zeppelin/pull/4715",
        ],
        "modules": [],
        "tags": [
            "web",
            "scanner",
            "zeppelin",
            "apache",
            "version",
            "cve-2024-31866",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/api/version"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(8080, "Zeppelin HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "URL path prefix if Zeppelin is not at site root", required=False)

    @staticmethod
    def _version_tuple(value: str) -> Tuple[int, ...]:
        parts = []
        for token in str(value or "").split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _normalize_base(self) -> str:
        path = str(self.base_path or "/").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        return path.rstrip("/")

    def _path(self, suffix: str) -> str:
        base = self._normalize_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    def _is_vulnerable(self, version: str) -> bool:
        current = self._version_tuple(version)
        return (
            current >= self._version_tuple(_AFFECTED_MIN)
            and current < self._version_tuple(_FIXED_VERSION)
        )

    def _extract_version(self, data: dict) -> str:
        body = data.get("body")
        if isinstance(body, dict):
            version = str(body.get("version") or "").strip()
            if version:
                return version
        for key in ("version", "zeppelinVersion"):
            version = str(data.get(key) or "").strip()
            if version:
                return version
        return ""

    def run(self):
        try:
            timeout = max(int(self.timeout or 10), 10)
            response = self.http_request(
                method="GET",
                path=self._path("/api/version"),
                allow_redirects=True,
                timeout=timeout,
            )
            data, err = parse_json_response(response)
            if err or not data:
                return False

            version = self._extract_version(data)
            if not version:
                status = str(data.get("status") or "").upper()
                if status and status != "OK":
                    return False
                self.set_info(
                    severity="info",
                    cve="CVE-2024-31866",
                    reason="Apache Zeppelin API detected but version could not be extracted",
                    path=self._path("/api/version"),
                )
                return True

            print_success(f"Apache Zeppelin {version} detected")
            if self._is_vulnerable(version):
                self.set_info(
                    severity="critical",
                    cve="CVE-2024-31866",
                    reason=(
                        f"Apache Zeppelin {version} is in the CVE-2024-31866 range "
                        f"(>= {_AFFECTED_MIN}, < {_FIXED_VERSION})"
                    ),
                    version=version,
                    confidence="high",
                    path=self._path("/api/version"),
                )
                return True

            self.set_info(
                severity="info",
                reason=(
                    f"Apache Zeppelin {version} detected; outside CVE-2024-31866 "
                    f"affected range (fixed in {_FIXED_VERSION}+)"
                ),
                version=version,
                path=self._path("/api/version"),
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
