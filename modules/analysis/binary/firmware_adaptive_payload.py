#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Firmware arch → adaptive payload/listener plan.

Scans ELF headers, selects BusyBox/CMD or raw payload, pairs with
adaptive_reverse_tcp or reverse_tcp, and prints operator commands.
"""

import json
import os
import time

from kittysploit import *

from lib.firmware.arch import FirmwareArch


class Module(Analysis, FirmwareArch):
    __info__ = {
        "name": "Firmware → adaptive payload plan",
        "description": (
            "Detect firmware CPU architecture from ELF headers, select the best "
            "payload (BusyBox/CMD vs raw) and listener (adaptive vs reverse_tcp), "
            "then emit a ready-to-run CLI command sequence."
        ),
        "author": ["KittySploit Team"],
        "references": [],
        "cve": "",
        "tags": ["firmware", "binary", "mips", "arm", "iot", "payload", "adaptive"],
        "agent": {
            "risk": "passive",
            "effects": ["local_analysis"],
            "produces": ["tech_hints"],
            "chain": {
                "produces_capabilities": ["payload_plan"],
                "suggested_followups": [
                    "listeners/multi/adaptive_reverse_tcp",
                    "payloads/singles/cmd/unix/busybox_reverse_tcp",
                    "analysis/binary/firmware_arch_suggest",
                ],
            },
        },
    }

    firmware_path = OptString("", "Path to firmware file", required=True)
    preference = OptChoice(
        "auto",
        "Payload preference: auto (embedded→BusyBox), cmd, raw",
        False,
        choices=["auto", "cmd", "raw"],
    )
    lhost = OptString("127.0.0.1", "LHOST for generated operator commands", False)
    lport = OptPort(4444, "LPORT for generated operator commands", False)
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
    save_local = OptBool(True, "Save plan JSON under ./output", False)
    show_commands = OptBool(True, "Print use/set/run/generate command sequence", False)

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
        if not self.check():
            return False
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
            print_error(f"Firmware adaptive plan failed: {exc}")
            return False

        print_status(f"Scanned {report['scanned_bytes']} bytes from {path}")
        for line in self.summarize_arch_report(report):
            if line.startswith("Primary") or line.startswith("Selected"):
                print_success(line)
            elif line.startswith("Reason"):
                print_info(line)
            else:
                print_status(line)

        plan = report.get("adaptive_plan") if isinstance(report.get("adaptive_plan"), dict) else {}
        if not report.get("primary_arch") or not plan.get("primary_payload"):
            print_warning(
                "No adaptive plan — try raising scan_mb or run "
                "analysis/binary/firmware_extractor_advanced first"
            )
            return False

        if bool(self.show_commands):
            print_status("Operator sequence:")
            for cmd in plan.get("commands") or []:
                print_info(f"  {cmd}")

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            out = os.path.join("output", f"firmware_adaptive_plan_{stamp}.json")
            with open(out, "w", encoding="utf-8") as fh:
                json.dump({"report": {
                    "firmware_path": report.get("firmware_path"),
                    "primary_arch": report.get("primary_arch"),
                    "arch_counts": report.get("arch_counts"),
                    "suggested_payloads": report.get("suggested_payloads"),
                    "adaptive_plan": plan,
                }}, fh, indent=2)
            print_success(f"Saved ./{out}")

        return report
