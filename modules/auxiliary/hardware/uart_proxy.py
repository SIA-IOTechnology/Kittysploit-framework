#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UART proxy auxiliary — bidirectional serial MITM for hardware / IoT analysis.

Place a USB-serial adapter on each side of a UART link (MCU ↔ radio module,
debug header, etc.) to capture, modify, and replay traffic in flight.
Inspired by Akheron (https://github.com/akheron/uart-proxy).
"""

from __future__ import annotations

from pathlib import Path

from kittysploit import *
from lib.protocols.hardware.uart_proxy import (
    ChecksumMethod,
    UartProxy,
    UartProxyConfig,
    list_serial_ports,
    parse_delimiter_list,
    parse_replace_rules,
    replay_capture,
)


class Module(Auxiliary):
    __info__ = {
        "name": "UART Proxy",
        "description": (
            "Bidirectional UART MITM between two serial devices. Captures hex "
            "traffic, applies in-flight byte-pattern replacements with optional "
            "checksum recalculation, and replays Akheron-style capture files. "
            "Useful for embedded firmware, IoT, and OT hardware reverse engineering."
        ),
        "author": ["KittySploit Team"],
        "tags": [
            "hardware",
            "uart",
            "serial",
            "iot",
            "embedded",
            "mitm",
            "capture",
            "replay",
            "ot",
        ],
        "references": [
            "https://attack.mitre.org/techniques/T0842/",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T0842"],
            "prerequisites": [
                "Two USB-serial adapters wired between the target UART endpoints",
                "pyserial installed on the operator host",
                "Read/write access to /dev/ttyUSB* or COM ports",
            ],
            "detections": [
                "Physical tap on UART wiring",
            ],
            "artifacts": [
                "Optional hex capture file on operator host",
            ],
        },
        "agent": {
            "risk": "active",
            "effects": ["hardware_sniff"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints"],
            "chain": {
                "produces_capabilities": ["uart_traffic"],
                "suggested_followups": [
                    "analysis/binary/firmware_extractor_advanced",
                    "plugins/minicom",
                ],
            },
        },
    }

    action = OptChoice(
        "proxy",
        "Operation mode",
        True,
        ["proxy", "replay", "list"],
    )
    port_a = OptString("/dev/ttyUSB0", "Serial device for endpoint A", False)
    port_b = OptString("/dev/ttyUSB1", "Serial device for endpoint B", False)
    baud = OptInteger(115200, "Default baud rate for both ports", False)
    baud_a = OptInteger(0, "Baud rate for port A (0 = use BAUD)", False, advanced=True)
    baud_b = OptInteger(0, "Baud rate for port B (0 = use BAUD)", False, advanced=True)
    duration = OptInteger(0, "Proxy duration in seconds (0 = until Ctrl+C)", False)
    capture_file = OptString("", "Save captured traffic to this file", False)
    replace_a = OptString(
        "",
        "Pattern replacements on A->B traffic (e.g. 0x31 -> 0x32, 0x01 0x02 -> 0x03)",
        False,
        advanced=True,
    )
    replace_b = OptString(
        "",
        "Pattern replacements on B->A traffic",
        False,
        advanced=True,
    )
    checksum_a = OptChoice(
        "",
        "Checksum method after replacements on A->B",
        False,
        ["", "xor", "mod256", "mod256+1", "2s"],
    )
    checksum_b = OptChoice(
        "",
        "Checksum method after replacements on B->A",
        False,
        ["", "xor", "mod256", "mod256+1", "2s"],
    )
    exclude_delim_checksum = OptBool(
        False,
        "Exclude start delimiter bytes from checksum calculation",
        False,
        advanced=True,
    )
    start_delim = OptString(
        "",
        "Start-of-message hex delimiter(s), comma-separated (checksum scope only)",
        False,
        advanced=True,
    )
    replay_file = OptString("", "Capture file to replay (ACTION=replay)", False)
    replay_lines = OptString("", "Lines to replay: 1,4,2-10 (empty = all)", False, advanced=True)
    watch = OptBool(True, "Print hex traffic to the console", False)
    verbose = OptBool(False, "Verbose port listing (ACTION=list)", False, advanced=True)

    def check(self):
        action = str(self.action or "proxy").strip().lower()
        if action == "list":
            return True
        try:
            import serial  # noqa: F401
        except ImportError:
            print_error("pyserial is not installed. Install it with: pip install pyserial")
            return False
        if action == "replay":
            replay_path = str(self.replay_file or "").strip()
            if not replay_path:
                print_error("REPLAY_FILE is required when ACTION=replay")
                return False
            if not Path(replay_path).is_file():
                print_error(f"Replay file not found: {replay_path}")
                return False
            if not str(self.port_a or "").strip() or not str(self.port_b or "").strip():
                print_error("PORT_A and PORT_B are required for replay (outbound port is auto-selected)")
                return False
            return True
        if not str(self.port_a or "").strip() or not str(self.port_b or "").strip():
            print_error("PORT_A and PORT_B are required for proxy mode")
            return False
        if str(self.port_a).strip() == str(self.port_b).strip():
            print_warning("PORT_A and PORT_B are the same device — this is usually unintended")
        return True

    def run(self):
        action = str(self.action or "proxy").strip().lower()
        if action == "list":
            return self._run_list()
        if action == "replay":
            return self._run_replay()
        return self._run_proxy()

    def _baud_rates(self) -> tuple[int, int]:
        default = max(1, int(self.baud or 115200))
        baud_a = int(self.baud_a or 0) or default
        baud_b = int(self.baud_b or 0) or default
        return baud_a, baud_b

    def _build_config(self) -> UartProxyConfig:
        baud_a, baud_b = self._baud_rates()
        capture = str(self.capture_file or "").strip() or None
        return UartProxyConfig(
            port_a=str(self.port_a).strip(),
            port_b=str(self.port_b).strip(),
            baud_a=baud_a,
            baud_b=baud_b,
            replace_a=parse_replace_rules(str(self.replace_a or "")),
            replace_b=parse_replace_rules(str(self.replace_b or "")),
            checksum_a=ChecksumMethod.from_name(str(self.checksum_a or "")),
            checksum_b=ChecksumMethod.from_name(str(self.checksum_b or "")),
            exclude_delim_checksum=bool(self.exclude_delim_checksum),
            start_delims=parse_delimiter_list(str(self.start_delim or "")),
            capture_path=capture,
            watch=bool(self.watch),
        )

    def _run_list(self) -> bool:
        print_info("Available serial ports")
        print_info("=" * 60)
        ports = list_serial_ports(verbose=bool(self.verbose))
        if ports:
            print_success(f"Found {len(ports)} serial port(s)")
            return True
        print_warning("No serial ports detected")
        return False

    def _run_proxy(self) -> bool:
        cfg = self._build_config()
        duration = max(0, int(self.duration or 0))
        proxy = UartProxy(cfg)

        print_info("UART proxy — bidirectional MITM")
        print_info("=" * 60)
        print_info(f"  A: {cfg.port_a} @ {cfg.baud_a} baud")
        print_info(f"  B: {cfg.port_b} @ {cfg.baud_b} baud")
        if cfg.capture_path:
            print_info(f"  Capture: {cfg.capture_path}")
        if cfg.replace_a:
            print_info(f"  Replace A->B: {len(cfg.replace_a)} rule(s)")
        if cfg.replace_b:
            print_info(f"  Replace B->A: {len(cfg.replace_b)} rule(s)")
        if duration:
            print_info(f"  Duration: {duration}s")
        else:
            print_info("  Duration: until Ctrl+C")
        print_info("=" * 60)

        try:
            proxy.start()
        except (RuntimeError, ValueError) as exc:
            print_error(str(exc))
            return False

        print_success(f"Traffic passing {cfg.port_a} <-> {cfg.port_b}")
        if cfg.watch:
            print_info("Hex output (direction: bytes):")
            print_info("")

        try:
            proxy.run_for(duration)
        except KeyboardInterrupt:
            print_info("")
            print_warning("Interrupted — stopping UART proxy")
        finally:
            proxy.stop()

        if cfg.capture_path:
            print_success(f"Capture saved: {cfg.capture_path}")
        print_info("UART proxy stopped")
        return True

    def _run_replay(self) -> bool:
        baud_a, baud_b = self._baud_rates()
        replay_path = str(self.replay_file).strip()
        line_spec = str(self.replay_lines or "").strip()
        port_a = str(self.port_a).strip()
        port_b = str(self.port_b).strip()

        print_info(f"Replaying capture: {replay_path}")
        try:
            count = replay_capture(
                replay_path,
                port_a=port_a,
                port_b=port_b,
                baud_a=baud_a,
                baud_b=baud_b,
                line_spec=line_spec,
                replace_a=parse_replace_rules(str(self.replace_a or "")),
                replace_b=parse_replace_rules(str(self.replace_b or "")),
                checksum_a=ChecksumMethod.from_name(str(self.checksum_a or "")),
                checksum_b=ChecksumMethod.from_name(str(self.checksum_b or "")),
                start_delims=parse_delimiter_list(str(self.start_delim or "")),
                exclude_delim_checksum=bool(self.exclude_delim_checksum),
                watch=bool(self.watch),
            )
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            print_error(str(exc))
            return False

        if count:
            print_success(f"Replayed {count} line(s) from {replay_path}")
            return True
        print_warning("No lines were replayed — check REPLAY_LINES and capture format")
        return False
