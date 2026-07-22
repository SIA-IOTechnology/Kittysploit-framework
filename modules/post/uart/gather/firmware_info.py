#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UART Firmware Info - Probes serial console for OS / firmware identity
"""

from kittysploit import *
from lib.protocols.hardware.uart_session_mixin import UartSessionMixin
import json
from datetime import datetime
import re


DEFAULT_COMMANDS = [
    "uname -a",
    "cat /proc/version",
    "cat /etc/os-release",
    "cat /etc/issue",
    "cat /proc/cpuinfo",
    "cat /proc/cmdline",
    "fw_printenv 2>/dev/null | head -n 20",
    "version",
    "help",
]


class Module(Post, UartSessionMixin):
    __info__ = {
        "name": "UART Firmware Info",
        "description": (
            "Probes a UART console with read-only commands to collect kernel, "
            "OS release, CPU, and bootloader / firmware identity strings"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.UART,
        "tags": ["hardware", "uart", "gather", "firmware", "embedded"],
        "references": [
            "https://attack.mitre.org/techniques/T0842/",
            "https://attack.mitre.org/techniques/T0882/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["recon"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "firmware_identity"],
            "cost": 0.7,
            "noise": 0.2,
            "value": 1.4,
            "chain": {
                "consumes_capabilities": ["uart_session"],
                "produces_capabilities": [
                    {"capability": "firmware_identity", "from_detail": "firmware_info"},
                ],
                "suggested_followups": [
                    "post/uart/gather/busybox_audit",
                    "post/uart/gather/banner",
                ],
            },
        },
    }

    commands = OptString(
        "",
        "Comma-separated commands to run (empty = built-in probe set)",
        required=False,
    )
    wait = OptFloat(1.2, "Seconds to wait for each command response", required=True)
    newline = OptString("\\r\\n", "Newline sequence", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)
    store_results = OptBool(True, "Store results in session.data['firmware_info']", required=False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        session = self.framework.session_manager.get_session(sid) if self.framework else None
        if not session:
            print_error("Session not found")
            return False
        if str(session.session_type).lower() != SessionType.UART.value:
            print_error(f"Session is not UART (type: {session.session_type})")
            return False
        try:
            self.open_uart()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def _newline(self) -> str:
        raw = str(self.newline or "\\r\\n")
        return raw.encode("utf-8").decode("unicode_escape")

    def _command_list(self):
        raw = str(self.commands or "").strip()
        if not raw:
            return list(DEFAULT_COMMANDS)
        return [part.strip() for part in raw.split(",") if part.strip()]

    def run(self):
        client = self.open_uart()
        wait = max(0.2, float(self.wait or 1.2))
        newline = self._newline()
        cmds = self._command_list()
        info = client.connection_summary()

        print_info("=" * 80)
        print_success("UART Firmware Info")
        print_info(f"Device   : {info.get('port')} @ {info.get('baudrate')}")
        print_info(f"Probes   : {len(cmds)}")
        print_info("=" * 80)

        results = []
        summary = {}
        for cmd in cmds:
            print_status(f"$ {cmd}")
            exchange = client.exchange(cmd, wait=wait, newline=newline)
            entry = {
                "command": cmd,
                "success": exchange.success,
                "response": exchange.text,
                "error": exchange.error,
            }
            results.append(entry)
            if exchange.success and exchange.text.strip():
                preview = exchange.text.strip()
                if len(preview) > 500:
                    preview = preview[:500] + "..."
                print_info(preview)
                self._enrich_summary(summary, cmd, exchange.text)
            elif exchange.error:
                print_warning(exchange.error)

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "device": info.get("port"),
            "baudrate": info.get("baudrate"),
            "summary": summary,
            "probes": results,
        }

        print_info("-" * 80)
        if summary:
            print_success("Extracted identity")
            for key, value in summary.items():
                print_info(f"  {key}: {value}")
        else:
            print_warning("No clear firmware identity strings extracted")

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["firmware_info"] = report
                session.data = data

        out = str(self.output_file or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2)
                print_success(f"Wrote report to {out}")
            except OSError as exc:
                print_error(f"Failed to write output: {exc}")

        return True

    def _enrich_summary(self, summary: dict, cmd: str, text: str) -> None:
        cleaned = text.strip()
        if "uname" in cmd and "Linux" in cleaned:
            for line in cleaned.splitlines():
                if "Linux" in line and "uname" not in line.lower():
                    summary.setdefault("uname", line.strip())
                    break
        if "/proc/version" in cmd:
            m = re.search(r"Linux version [^\r\n]+", cleaned)
            if m:
                summary.setdefault("kernel", m.group(0).strip())
        if "os-release" in cmd:
            for line in cleaned.splitlines():
                if line.startswith("PRETTY_NAME="):
                    summary.setdefault("os", line.split("=", 1)[1].strip().strip('"'))
                elif line.startswith("ID="):
                    summary.setdefault("os_id", line.split("=", 1)[1].strip().strip('"'))
        if "cpuinfo" in cmd:
            m = re.search(r"model name\s*:\s*(.+)", cleaned, re.I)
            if m:
                summary.setdefault("cpu", m.group(1).strip())
            m = re.search(r"Hardware\s*:\s*(.+)", cleaned, re.I)
            if m:
                summary.setdefault("soc", m.group(1).strip())
        if "cmdline" in cmd:
            for line in cleaned.splitlines():
                line = line.strip()
                if line and "cat /proc/cmdline" not in line and not line.endswith("#") and not line.endswith("$"):
                    summary.setdefault("cmdline", line)
                    break
        if cmd.strip() in ("version", "help") and "U-Boot" in cleaned:
            m = re.search(r"U-Boot[^\r\n]+", cleaned, re.I)
            if m:
                summary.setdefault("bootloader", m.group(0).strip())
