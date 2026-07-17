#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE gather — subscribe to notifications/indications and capture traffic."""

from kittysploit import *
from lib.protocols.ble.ble_session_mixin import BleSessionMixin
from lib.protocols.ble.ble_client import normalize_uuid
import json
from datetime import datetime


class Module(Post, BleSessionMixin):
    __info__ = {
        "name": "BLE Notify Capture",
        "description": (
            "Subscribes to GATT notifications/indications and captures values "
            "for a timed window"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.BLE,
        "tags": ["ble", "bluetooth", "iot", "gather", "notify", "gatt"],
        "agent": {
            "risk": "intrusive",
            "effects": ["recon", "wireless_sniff"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints"],
            "chain": {
                "consumes_capabilities": ["ble_characteristics"],
                "produces_capabilities": [{"capability": "ble_notify_traffic", "from_detail": ""}],
                "suggested_followups": [
                    "post/ble/manage/write_characteristic",
                ],
            },
        },
    }

    uuid = OptString(
        "",
        "Characteristic UUID to notify on (empty = all notify/indicate chars)",
        False,
    )
    duration = OptFloat(5.0, "Capture duration in seconds", True)
    auto_discover = OptBool(True, "Auto-pick notify/indicate characteristics when uuid empty", False)
    export_json = OptString("", "Optional JSON output file", False)
    store_results = OptBool(True, "Store capture in session.data['ble_notify_capture']", False)

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
        client = self.open_ble()
        info = client.connection_summary()
        duration = max(0.2, float(self.duration or 5.0))
        target = str(self.uuid or "").strip()

        uuids = []
        if target:
            uuids = [normalize_uuid(target) or target]
        elif bool(self.auto_discover):
            for svc in client.get_services():
                for char in svc.characteristics:
                    props = set(p.lower() for p in char.properties)
                    if "notify" in props or "indicate" in props:
                        uuids.append(char.uuid)
        else:
            print_error("uuid is required when auto_discover is false")
            return False

        if not uuids:
            print_warning("No notify/indicate characteristics found")
            return False

        # Deduplicate
        seen = set()
        unique = []
        for u in uuids:
            key = normalize_uuid(u) or u
            if key not in seen:
                seen.add(key)
                unique.append(u)
        uuids = unique

        print_info("=" * 80)
        print_success("BLE Notify Capture")
        print_info(f"  device   : {info.get('address')}")
        print_info(f"  duration : {duration}s")
        print_info(f"  chars    : {len(uuids)}")
        for u in uuids[:10]:
            print_info(f"    - {u}")
        print_info("=" * 80)

        print_status("Capturing notifications...")
        try:
            events = client.capture_notifications(uuids, duration=duration, clear=True)
        except Exception as exc:
            print_error(f"Notify capture failed: {exc}")
            return False

        print_success(f"Captured {len(events)} notification(s)")
        for event in events[:40]:
            ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in event.data)
            print_info(f"  {event.uuid}  {event.hex}  | {ascii_preview}")
        if len(events) > 40:
            print_info(f"  ... {len(events) - 40} more")

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "address": info.get("address"),
            "duration": duration,
            "uuids": uuids,
            "count": len(events),
            "events": [
                {
                    "uuid": e.uuid,
                    "hex": e.hex,
                    "timestamp": e.timestamp,
                    "length": len(e.data),
                }
                for e in events
            ],
        }

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["ble_notify_capture"] = report
                session.data = data

        out = str(self.export_json or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2)
                print_success(f"Exported to {out}")
            except OSError as exc:
                print_error(f"Export failed: {exc}")

        return True
