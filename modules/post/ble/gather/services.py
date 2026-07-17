#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE gather — list GATT services on a connected peripheral."""

from kittysploit import *
from lib.protocols.ble.ble_session_mixin import BleSessionMixin
import json


class Module(Post, BleSessionMixin):
    __info__ = {
        "name": "BLE GATT Services",
        "description": "Enumerates GATT services exposed by a connected BLE peripheral",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.BLE,
        "tags": ["ble", "bluetooth", "iot", "gather", "gatt"],
        "references": [
            "https://www.bluetooth.com/specifications/gatt/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["recon"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints"],
            "chain": {
                "consumes_capabilities": ["ble_session"],
                "produces_capabilities": [{"capability": "ble_gatt_map", "from_detail": "services"}],
                "suggested_followups": [
                    "post/ble/gather/characteristics",
                    "post/ble/manage/read_characteristic",
                ],
            },
        },
    }

    refresh = OptBool(True, "Force rediscovery of services", False)
    export_json = OptString("", "Optional JSON output file", False)
    store_results = OptBool(True, "Store results in session.data['ble_services']", False)

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
        print_status(f"Enumerating GATT services on {info.get('address')}...")
        services = client.get_services(refresh=bool(self.refresh))

        rows = []
        print_info("=" * 80)
        print_success(f"Found {len(services)} service(s)")
        for svc in services:
            row = {
                "uuid": svc.uuid,
                "handle": svc.handle,
                "description": svc.description,
                "characteristic_count": len(svc.characteristics),
                "characteristics": [c.uuid for c in svc.characteristics],
            }
            rows.append(row)
            print_info(f"  {svc.uuid}  handle={svc.handle}  chars={len(svc.characteristics)}")

        report = {
            "address": info.get("address"),
            "name": info.get("name"),
            "count": len(rows),
            "services": rows,
        }

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["ble_services"] = report
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
