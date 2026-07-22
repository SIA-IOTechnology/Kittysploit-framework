#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE manage — read a GATT characteristic value."""

from kittysploit import *
from lib.protocols.ble.ble_session_mixin import BleSessionMixin
from lib.protocols.ble.ble_client import normalize_uuid


class Module(Post, BleSessionMixin):
    __info__ = {
        "name": "BLE Read Characteristic",
        "description": "Reads a GATT characteristic value from a connected BLE peripheral",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.BLE,
        "tags": ["ble", "bluetooth", "iot", "manage", "gatt", "read"],
        "agent": {
            "risk": "intrusive",
            "effects": ["recon"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints"],
            "chain": {
                "consumes_capabilities": ["ble_characteristics"],
                "produces_capabilities": [{"capability": "ble_char_value", "from_detail": ""}],
                "suggested_followups": [
                    "post/ble/manage/write_characteristic",
                    "post/ble/gather/notify_capture",
                ],
            },
        },
    }

    uuid = OptString("", "Characteristic UUID (short 0x2A00 or full)", True)
    store_results = OptBool(True, "Store last read in session.data['ble_last_read']", False)

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
        if not str(self.uuid or "").strip():
            print_error("uuid is required")
            return False
        try:
            self.open_ble()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        client = self.open_ble()
        uuid = str(self.uuid).strip()
        norm = normalize_uuid(uuid) or uuid
        info = client.connection_summary()

        print_status(f"Reading {norm} on {info.get('address')}...")
        try:
            data = client.read_characteristic(norm)
        except Exception as exc:
            print_error(f"Read failed: {exc}")
            return False

        ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        print_success(f"Read {len(data)} byte(s)")
        print_info(f"  hex   : {data.hex()}")
        print_info(f"  ascii : {ascii_preview}")

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                sdata = session.data if isinstance(session.data, dict) else {}
                sdata["ble_last_read"] = {
                    "uuid": norm,
                    "hex": data.hex(),
                    "length": len(data),
                    "ascii": ascii_preview,
                }
                session.data = sdata

        return True
