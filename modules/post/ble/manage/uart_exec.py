#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Execute a command over BLE UART/NUS pivot channel."""

from kittysploit import *
from lib.protocols.ble.ble_session_mixin import BleSessionMixin


class Module(Post, BleSessionMixin):
    __info__ = {
        "name": "BLE UART exec",
        "description": (
            "Send a command string over a BLE UART/NUS write characteristic and "
            "collect the notify response (serial-over-GATT pivot)."
        ),
        "author": "KittySploit Team",
        "session_type": SessionType.BLE,
        "tags": ["ble", "bluetooth", "iot", "manage", "uart", "pivot", "nus"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["ble_uart_pivot", "ble_gatt_map"],
                "produces_capabilities": ["ble_uart_pivot", "shell"],
                "suggested_followups": [
                    "post/ble/gather/uart_probe",
                    "post/shell/linux/busybox/firmware_info",
                ],
            },
            "requires": {"capabilities_any": ["ble_uart_pivot", "ble_gatt_map"]},
        },
    }

    command = OptString("help", "Command / text to send on the UART write characteristic", True)
    write_uuid = OptString("", "Override write UUID (empty = auto-detect)", False)
    notify_uuid = OptString("", "Override notify UUID (empty = auto-detect)", False)
    timeout = OptFloat(4.0, "Seconds to collect notify response", False)
    mtu_chunk = OptInteger(20, "ATT write chunk size", False, advanced=True)
    newline = OptBool(True, "Append newline to command", False)
    dry_run = OptBool(False, "Resolve UART endpoints only — do not send", False)
    confirm = OptBool(False, "Must be True to send (safety latch)", True)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        session = self.framework.session_manager.get_session(sid) if self.framework else None
        if not session:
            print_error("Session not found")
            return False
        if str(session.session_type).lower() != SessionType.BLE.value:
            print_error(f"Session is not BLE (type: {session.session_type})")
            return False
        if not str(self.command or "").strip():
            print_error("command is required")
            return False
        try:
            self.open_ble()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        if not self.check():
            return False

        cmd = str(self.command or "").strip()
        if bool(self.dry_run):
            try:
                pivot = self.open_ble_uart(
                    write_uuid=str(self.write_uuid or ""),
                    notify_uuid=str(self.notify_uuid or ""),
                    mtu_chunk=int(self.mtu_chunk or 20),
                    auto_start=False,
                )
            except Exception as exc:
                print_error(str(exc))
                return False
            print_success(
                f"Dry run — would send via {pivot.profile_name} "
                f"write={pivot.write_uuid} cmd={cmd!r}"
            )
            return True

        if not bool(self.confirm):
            print_error("Set confirm=true to send over BLE UART (lab only)")
            return False

        print_warning(f"BLE UART exec: {cmd!r}")
        try:
            pivot = self.open_ble_uart(
                write_uuid=str(self.write_uuid or ""),
                notify_uuid=str(self.notify_uuid or ""),
                mtu_chunk=int(self.mtu_chunk or 20),
                auto_start=True,
            )
            result = pivot.exec_command(
                cmd,
                timeout=float(self.timeout or 4),
                newline=bool(self.newline),
            )
            pivot.stop()
        except Exception as exc:
            print_error(str(exc))
            return False

        if result.error and not result.response:
            print_error(result.error)
            return False

        print_success(
            f"Sent via {pivot.profile_name} — {len(result.response)} response byte(s)"
        )
        if result.text.strip():
            print_info(result.text.rstrip())
        elif result.response:
            print_info(result.response.hex())
        else:
            print_warning("No notify response (device may be quiet or needs pairing)")
        return True
