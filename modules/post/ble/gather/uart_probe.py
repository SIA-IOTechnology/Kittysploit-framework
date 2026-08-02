#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Probe BLE UART / Nordic NUS channels for shell pivot."""

from kittysploit import *
from lib.protocols.ble.ble_session_mixin import BleSessionMixin
from lib.protocols.ble.pivot import discover_uart_endpoints


class Module(Post, BleSessionMixin):
    __info__ = {
        "name": "BLE UART pivot probe",
        "description": (
            "Detect Nordic NUS and common UART-over-GATT profiles on a BLE session "
            "for interactive pivot (uart_exec / shell commands)."
        ),
        "author": "KittySploit Team",
        "session_type": SessionType.BLE,
        "tags": ["ble", "bluetooth", "iot", "gather", "uart", "pivot", "nus"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "consumes_capabilities": ["ble_gatt_map", "ble_characteristics"],
                "produces_capabilities": ["ble_uart_pivot"],
                "suggested_followups": [
                    "post/ble/manage/uart_exec",
                    "post/ble/gather/notify_capture",
                ],
            },
            "requires": {"capabilities_any": ["ble_gatt_map", "ble_characteristics"]},
        },
    }

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
        try:
            self.open_ble()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        if not self.check():
            return False
        client = self.open_ble()
        probe = discover_uart_endpoints(client)
        if not probe.found:
            print_error(probe.error or "No UART/NUS endpoints found")
            return False

        print_success(f"Found {len(probe.endpoints)} UART-style endpoint(s)")
        for ep in probe.endpoints:
            mark = "PRIMARY" if probe.primary and ep.write_uuid == probe.primary.write_uuid else "      "
            print_info(f"  [{mark}] {ep.name}")
            print_info(f"           write ={ep.write_uuid}")
            print_info(f"           notify={ep.notify_uuid}")

        session = self._resolve_session()
        if session:
            data = session.data if isinstance(session.data, dict) else {}
            primary = probe.primary
            data["ble_uart"] = {
                "profile": primary.name if primary else "",
                "write_uuid": primary.write_uuid if primary else "",
                "notify_uuid": primary.notify_uuid if primary else "",
                "endpoints": [
                    {
                        "name": e.name,
                        "write_uuid": e.write_uuid,
                        "notify_uuid": e.notify_uuid,
                    }
                    for e in probe.endpoints
                ],
            }
            session.data = data
        print_status("Next: post/ble/manage/uart_exec or shell: uart_exec <cmd>")
        return True
