#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE gather — list GATT characteristics and properties."""

from kittysploit import *
from lib.protocols.ble.ble_session_mixin import BleSessionMixin
import json


class Module(Post, BleSessionMixin):
    __info__ = {
        "name": "BLE GATT Characteristics",
        "description": "Enumerates GATT characteristics (UUID, handle, properties) for a BLE session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.BLE,
        "tags": ["ble", "bluetooth", "iot", "gather", "gatt"],
        "agent": {
            "risk": "passive",
            "effects": ["recon"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints"],
            "chain": {
                "consumes_capabilities": ["ble_gatt_map"],
                "produces_capabilities": [{"capability": "ble_characteristics", "from_detail": ""}],
                "suggested_followups": [
                    "post/ble/manage/read_characteristic",
                    "post/ble/gather/notify_capture",
                    "post/ble/manage/write_characteristic",
                ],
            },
        },
    }

    service_uuid = OptString("", "Filter by service UUID (empty = all)", False)
    refresh = OptBool(False, "Force rediscovery before listing", False)
    export_json = OptString("", "Optional JSON output file", False)
    store_results = OptBool(True, "Store results in session.data['ble_characteristics']", False)

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
        from lib.protocols.ble.ble_client import normalize_uuid

        client = self.open_ble()
        info = client.connection_summary()
        filter_svc = normalize_uuid(str(self.service_uuid or "").strip()) if self.service_uuid else ""

        print_status(f"Enumerating characteristics on {info.get('address')}...")
        services = client.get_services(refresh=bool(self.refresh))

        rows = []
        print_info("=" * 80)
        for svc in services:
            if filter_svc and normalize_uuid(svc.uuid) != filter_svc and svc.uuid.lower() != str(self.service_uuid).lower():
                continue
            print_success(f"Service {svc.uuid}")
            for char in svc.characteristics:
                row = {
                    "service_uuid": svc.uuid,
                    "uuid": char.uuid,
                    "handle": char.handle,
                    "properties": char.properties,
                    "description": char.description,
                    "descriptors": char.descriptors,
                }
                rows.append(row)
                props = ",".join(char.properties) if char.properties else "-"
                print_info(f"  {char.uuid}  handle={char.handle}  [{props}]")

        print_info("-" * 80)
        print_success(f"Total characteristics: {len(rows)}")

        report = {
            "address": info.get("address"),
            "filter_service": str(self.service_uuid or ""),
            "count": len(rows),
            "characteristics": rows,
        }

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["ble_characteristics"] = report
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
