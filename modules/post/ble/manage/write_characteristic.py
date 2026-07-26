#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE manage — write a GATT characteristic value."""

from kittysploit import *
from lib.protocols.ble.ble_session_mixin import BleSessionMixin
from lib.protocols.ble.ble_client import normalize_uuid


def _parse_payload(value: str, encoding: str) -> bytes:
    encoding = (encoding or "hex").strip().lower()
    text = str(value or "")
    if encoding == "hex":
        cleaned = text.lower().replace("0x", " ").replace(",", " ").replace(":", " ")
        parts = cleaned.split()
        if parts:
            return bytes(int(p, 16) & 0xFF for p in parts)
        cleaned = "".join(ch for ch in text.lower() if ch in "0123456789abcdef")
        if len(cleaned) % 2:
            raise ValueError("odd-length hex string")
        return bytes.fromhex(cleaned) if cleaned else b""
    if encoding == "ascii":
        return text.encode("ascii", errors="replace")
    if encoding == "utf8":
        return text.encode("utf-8", errors="replace")
    raise ValueError(f"unsupported encoding: {encoding}")


class Module(Post, BleSessionMixin):
    __info__ = {
        "name": "BLE Write Characteristic",
        "description": "Writes a value to a GATT characteristic on a connected BLE peripheral",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.BLE,
        "tags": ["ble", "bluetooth", "iot", "manage", "gatt", "write"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 1,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["ble_characteristics"],
                "produces_capabilities": [{"capability": "ble_write", "from_detail": ""}],
                "suggested_followups": [
                    "post/ble/manage/read_characteristic",
                    "post/ble/gather/notify_capture",
                ],
            },
        },
    }

    uuid = OptString("", "Characteristic UUID (short 0x2A00 or full)", True)
    value = OptString("", "Payload to write", True)
    encoding = OptChoice(
        "hex",
        "Payload encoding",
        False,
        choices=["hex", "ascii", "utf8"],
    )
    with_response = OptChoice(
        "auto",
        "Write mode: auto (from properties), true (write), false (write-without-response)",
        False,
        choices=["auto", "true", "false"],
    )
    dry_run = OptBool(False, "Validate only — do not write", False)

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
            _parse_payload(str(self.value or ""), str(self.encoding or "hex"))
        except ValueError as exc:
            print_error(str(exc))
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
        try:
            payload = _parse_payload(str(self.value or ""), str(self.encoding or "hex"))
        except ValueError as exc:
            print_error(str(exc))
            return False

        response = None
        mode = str(self.with_response or "auto").lower()
        if mode == "true":
            response = True
        elif mode == "false":
            response = False
        else:
            char = client.find_characteristic(norm)
            if char:
                props = set(p.lower() for p in char.properties)
                if "write" in props:
                    response = True
                elif "write-without-response" in props:
                    response = False

        info = client.connection_summary()
        print_info("=" * 80)
        print_success("BLE Write Characteristic")
        print_info(f"  device   : {info.get('address')}")
        print_info(f"  uuid     : {norm}")
        print_info(f"  payload  : {payload.hex()} ({len(payload)} bytes)")
        print_info(f"  response : {response if response is not None else 'default'}")
        print_info("=" * 80)

        if bool(self.dry_run):
            print_success("Dry run — write not sent")
            return True

        print_warning(f"Writing to {norm}...")
        try:
            client.write_characteristic(norm, payload, response=response)
        except Exception as exc:
            print_error(f"Write failed: {exc}")
            return False

        print_success("Write completed")
        session = self._resolve_session()
        if session:
            data = session.data if isinstance(session.data, dict) else {}
            data["ble_last_write"] = {
                "uuid": norm,
                "hex": payload.hex(),
                "length": len(payload),
                "with_response": response,
            }
            session.data = data
        return True
