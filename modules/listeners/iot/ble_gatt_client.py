#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE GATT bind listener — connects to a peripheral and opens a GATT session."""

from kittysploit import *
from lib.protocols.ble.ble_client import BleGattClient, bleak_available


class Module(Listener):
    __info__ = {
        "name": "BLE GATT Client",
        "description": (
            "Connects to a Bluetooth Low Energy peripheral over GATT and creates "
            "a session for service enumeration, read/write, and notify capture"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.BLE,
        "protocol": "ble-gatt",
        "dependencies": ["bleak"],
        "references": [
            "https://www.bluetooth.com/specifications/gatt/",
            "https://bleak.readthedocs.io/",
            "https://attack.mitre.org/techniques/T1016/",
        ],
    }

    address = OptString("", "BLE peripheral address / MAC (e.g. AA:BB:CC:DD:EE:FF)", True)
    adapter = OptString("", "Bluetooth adapter (empty = default; Linux e.g. hci0)", False)
    device_name = OptString("", "Optional friendly device name for session metadata", False)
    discover_on_connect = OptBool(True, "Enumerate GATT services after connect", True)

    def run(self):
        if not bleak_available():
            print_error("bleak is required but not installed")
            print_info("Install it with: pip install bleak")
            return False

        address = str(self.address or "").strip()
        if not address:
            print_error("address is required")
            print_info("Tip: discover devices with auxiliary/scanner/bluetooth/ble_scan")
            return False

        adapter = str(self.adapter or "").strip()
        name = str(self.device_name or "").strip()
        timeout = float(self.timeout or 20)

        print_status(f"Connecting to BLE GATT {address}" + (f" via {adapter}" if adapter else "") + "...")
        client = BleGattClient(address=address, adapter=adapter, timeout=timeout, name=name)
        try:
            if not client.connect():
                print_error(f"BLE connection failed for {address}")
                print_info("Ensure the adapter is up, the device is advertising, and not paired exclusively elsewhere")
                client.close()
                return False
        except Exception as exc:
            print_error(f"BLE connection error: {exc}")
            try:
                client.close()
            except Exception:
                pass
            return False

        services = []
        if bool(self.discover_on_connect):
            try:
                services = client.get_services(refresh=True)
                print_success(f"BLE GATT session established with {address}")
                print_info(f"  Services: {len(services)}")
                for svc in services[:8]:
                    print_info(f"    {svc.uuid}  ({len(svc.characteristics)} char)")
                if len(services) > 8:
                    print_info(f"    ... {len(services) - 8} more")
            except Exception as exc:
                print_warning(f"Connected but service discovery failed: {exc}")
                print_success(f"BLE GATT session established with {address}")
        else:
            print_success(f"BLE GATT session established with {address}")

        service_map = [
            {
                "uuid": s.uuid,
                "handle": s.handle,
                "characteristics": [
                    {"uuid": c.uuid, "handle": c.handle, "properties": c.properties}
                    for c in s.characteristics
                ],
            }
            for s in services
        ]

        additional_data = {
            "address": address,
            "name": name or client.name,
            "adapter": adapter,
            "timeout": timeout,
            "protocol": "ble-gatt",
            "platform": "iot",
            "services": service_map,
            "service_count": len(service_map),
        }
        return (client, address, 0, additional_data)

    def shutdown(self):
        try:
            if hasattr(self, "_session_connections"):
                for _sid, conn in list(self._session_connections.items()):
                    if conn and hasattr(conn, "close"):
                        try:
                            conn.close()
                        except Exception:
                            pass
        except Exception:
            pass
        return True
