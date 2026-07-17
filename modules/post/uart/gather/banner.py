#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UART Banner Gather - Captures console / boot banner from a serial session
"""

from kittysploit import *
from lib.protocols.hardware.uart_session_mixin import UartSessionMixin
import json
from datetime import datetime
import re


class Module(Post, UartSessionMixin):
    __info__ = {
        "name": "UART Capture Banner",
        "description": (
            "Captures the console banner, login prompt, or bootloader output "
            "from an active UART session"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.UART,
        "tags": ["hardware", "uart", "gather", "banner", "console"],
        "references": [
            "https://attack.mitre.org/techniques/T0842/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["recon"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints"],
            "cost": 0.3,
            "noise": 0.05,
            "value": 1.2,
            "chain": {
                "consumes_capabilities": ["uart_session"],
                "produces_capabilities": [
                    {"capability": "console_banner", "from_detail": "banner"},
                ],
                "suggested_followups": [
                    "post/uart/gather/firmware_info",
                    "post/uart/gather/busybox_audit",
                ],
            },
        },
    }

    duration = OptFloat(3.0, "Seconds to listen for banner output", required=True)
    nudge = OptBool(True, "Send a newline to elicit a prompt", required=True)
    newline = OptString("\\r\\n", "Newline sequence (\\r\\n, \\n, or \\r)", required=False)
    output_file = OptString("", "Optional JSON/text output file", required=False)
    store_results = OptBool(True, "Store banner in session.data['banner']", required=False)

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

    def run(self):
        client = self.open_uart()
        duration = max(0.2, float(self.duration or 3.0))
        info = client.connection_summary()

        print_info("=" * 80)
        print_success("UART Banner Capture")
        print_info(f"Device   : {info.get('port')} @ {info.get('baudrate')}")
        print_info(f"Duration : {duration}s  nudge={bool(self.nudge)}")
        print_info("=" * 80)

        print_status("Listening for console output...")
        raw = client.capture_banner(
            duration=duration,
            nudge=bool(self.nudge),
            newline=self._newline(),
        )
        text = client.decode_text(raw).strip("\x00")

        if not text.strip():
            print_warning("No banner data received (device silent or wrong baud rate)")
            return False

        hints = self._extract_hints(text)
        print_success(f"Captured {len(raw)} byte(s)")
        print_info("-" * 40)
        print_info(text if len(text) < 4000 else text[:4000] + "\n... [truncated]")
        print_info("-" * 40)
        for key, value in hints.items():
            if value:
                print_info(f"{key}: {value}")

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "device": info.get("port"),
            "baudrate": info.get("baudrate"),
            "banner": text,
            "banner_hex": raw.hex(),
            "hints": hints,
        }

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["banner"] = text
                data["banner_hints"] = hints
                session.data = data

        out = str(self.output_file or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    if out.lower().endswith(".json"):
                        json.dump(report, handle, indent=2)
                    else:
                        handle.write(text if text.endswith("\n") else text + "\n")
                print_success(f"Wrote output to {out}")
            except OSError as exc:
                print_error(f"Failed to write output: {exc}")

        return True

    def _extract_hints(self, text: str) -> dict:
        hints = {
            "login_prompt": bool(re.search(r"login\s*:", text, re.I)),
            "password_prompt": bool(re.search(r"password\s*:", text, re.I)),
            "uboot": bool(re.search(r"U-Boot|Hit any key to stop autoboot", text, re.I)),
            "busybox": bool(re.search(r"BusyBox", text, re.I)),
            "linux": bool(re.search(r"Linux version|GNU/Linux", text, re.I)),
        }
        m = re.search(r"(Linux version [^\r\n]+)", text)
        if m:
            hints["kernel"] = m.group(1).strip()
        m = re.search(r"(U-Boot\s+[^\r\n]+)", text, re.I)
        if m:
            hints["bootloader"] = m.group(1).strip()
        m = re.search(r"([\w./-]+[#$]|login:)", text)
        if m:
            hints["prompt_sample"] = m.group(1).strip()
        return hints
