#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UART Send Break - Sends a serial BREAK (and optional DTR pulse) on a UART session
"""

from kittysploit import *
from lib.protocols.hardware.uart_session_mixin import UartSessionMixin


class Module(Post, UartSessionMixin):
    __info__ = {
        "name": "UART Send Break",
        "description": (
            "Sends a UART BREAK signal to interrupt bootloaders (e.g. U-Boot) "
            "or force console attention; optionally pulses DTR as a reset line"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.UART,
        "tags": ["hardware", "uart", "manage", "break", "bootloader"],
        "references": [
            "https://pyserial.readthedocs.io/en/latest/pyserial_api.html#serial.Serial.send_break",
            "https://attack.mitre.org/techniques/T0842/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.3,
            "value": 1.1,
            "chain": {
                "consumes_capabilities": ["uart_session"],
                "produces_capabilities": [
                    {"capability": "bootloader_interrupt", "from_detail": ""},
                ],
                "suggested_followups": [
                    "post/uart/gather/banner",
                    "post/uart/gather/firmware_info",
                ],
            },
        },
    }

    duration_ms = OptInteger(250, "BREAK duration in milliseconds", required=True)
    count = OptInteger(1, "Number of BREAK pulses to send", required=True)
    pulse_dtr = OptBool(False, "Also pulse DTR (hardware reset on some boards)", required=False)
    dtr_low_ms = OptInteger(100, "DTR low duration in milliseconds", required=False, advanced=True)
    listen_after = OptFloat(2.0, "Seconds to capture output after BREAK", required=False)
    dry_run = OptBool(False, "Validate only — do not send BREAK", required=False)

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
        if int(self.duration_ms or 0) <= 0:
            print_error("duration_ms must be > 0")
            return False
        try:
            self.open_uart()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        client = self.open_uart()
        duration_s = max(0.01, int(self.duration_ms or 250) / 1000.0)
        count = max(1, min(20, int(self.count or 1)))
        info = client.connection_summary()

        print_info("=" * 80)
        print_success("UART Send Break")
        print_info(f"Device     : {info.get('port')} @ {info.get('baudrate')}")
        print_info(f"Duration   : {int(duration_s * 1000)} ms x {count}")
        print_info(f"Pulse DTR  : {bool(self.pulse_dtr)}")
        print_info("=" * 80)

        if bool(self.dry_run):
            print_success(
                f"Dry run — would send {count} BREAK pulse(s) "
                f"({int(duration_s * 1000)} ms) on {info.get('port')}"
            )
            return True

        print_warning(f"Sending BREAK on {info.get('port')}...")
        try:
            for i in range(count):
                client.send_break(duration=duration_s)
                print_status(f"  BREAK {i + 1}/{count} sent")
            if bool(self.pulse_dtr):
                low_ms = max(10, int(self.dtr_low_ms or 100))
                client.pulse_dtr(low_ms=low_ms)
                print_status(f"  DTR pulsed low for {low_ms} ms")
        except Exception as exc:
            print_error(f"Failed to send BREAK: {exc}")
            return False

        listen = max(0.0, float(self.listen_after or 0))
        if listen > 0:
            print_status(f"Listening {listen}s for post-BREAK output...")
            raw = client.read_for(listen)
            text = client.decode_text(raw).strip()
            if text:
                print_success("Output after BREAK:")
                print_info(text if len(text) < 4000 else text[:4000] + "\n... [truncated]")
                session = self._resolve_session()
                if session:
                    data = session.data if isinstance(session.data, dict) else {}
                    data["break_response"] = text
                    session.data = data
            else:
                print_warning("No output captured after BREAK")

        print_success("BREAK completed")
        return True
