#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scan a firmware image for ELF headers, detect CPU architecture, and suggest
matching KittySploit payloads (MIPS LE/BE, ARM LE, BusyBox, Zig, …).
"""

import os

from kittysploit import *

from lib.firmware.arch import FirmwareArch


class Module(Analysis, FirmwareArch):
    __info__ = {
        "name": "Firmware architecture → payload suggest",
        "description": (
            "Scan a local firmware blob for embedded ELF headers, infer "
            "architecture (mipsle/mipsbe/armle/arm64/x86/x64/…), recommend "
            "payloads, and show an adaptive listener plan."
        ),
        "author": ["KittySploit Team"],
        "references": [],
        "cve": "",
        "tags": ["firmware", "binary", "mips", "arm", "iot", "payload"],
        "agent": {
            "risk": "passive",
            "effects": ["local_analysis"],
            "produces": ["tech_hints"],
            "chain": {
                "produces_capabilities": ["payload_plan"],
                "suggested_followups": [
                    "analysis/binary/firmware_adaptive_payload",
                    "listeners/multi/adaptive_reverse_tcp",
                ],
            },
        },
    }

    firmware_path = OptString("", "Path to firmware file", required=True)
    preference = OptChoice(
        "auto",
        "Payload preference for adaptive plan: auto, cmd, raw",
        False,
        choices=["auto", "cmd", "raw"],
    )
    lhost = OptString("127.0.0.1", "LHOST hint for adaptive plan commands", False)
    lport = OptPort(4444, "LPORT hint for adaptive plan commands", False)
    scan_mb = OptInteger(
        8,
        "Megabytes read from the start of the file for ELF scan",
        required=False,
        advanced=True,
    )
    max_hits = OptInteger(
        32,
        "Maximum ELF headers to parse",
        required=False,
        advanced=True,
    )

    def check(self):
        path = str(self.firmware_path or "").strip()
        if not path:
            print_error("firmware_path is required")
            return False
        if not os.path.isfile(path):
            print_error(f"Firmware not found: {path}")
            return False
        return True

    def run(self):
        path = os.path.abspath(str(self.firmware_path).strip())
        try:
            report = self.analyze_firmware_arch(
                path,
                scan_mb=int(self.scan_mb or 8),
                max_hits=int(self.max_hits or 32),
                preference=str(self.preference or "auto"),
                lhost=str(self.lhost or "127.0.0.1"),
                lport=int(self.lport or 4444),
            )
        except Exception as exc:
            print_error(f"Firmware arch analysis failed: {exc}")
            return

        print_status(f"Scanned {report['scanned_bytes']} bytes from {path}")
        for line in self.summarize_arch_report(report):
            if line.startswith("Primary") or line.startswith("Selected"):
                print_success(line)
            elif line.startswith("Suggested") or line.startswith("Reason"):
                print_info(line)
            else:
                print_status(line)

        if not report.get("primary_arch"):
            print_warning(
                "Try raising scan_mb or run analysis/binary/firmware_extractor_advanced first"
            )
            return

        plan = report.get("adaptive_plan") or {}
        print_info(f"Default listener: {report.get('listener')}")
        if plan.get("commands"):
            print_status("Next: analysis/binary/firmware_adaptive_payload for full command plan")
        return report
