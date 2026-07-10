#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passively enumerate CDP and LLDP neighbors to map VLAN and switch context."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.vlan.vlan_client import Vlan_client


class Module(Auxiliary, Vlan_client):
    __info__ = {
        "name": "CDP / LLDP Neighbor Enumerator",
        "description": (
            "Passively capture Cisco CDP and IEEE 802.1AB LLDP frames on a switch "
            "access/trunk port to discover native VLAN, voice VLAN, port VLAN, and "
            "upstream switch identity."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "vlan", "cdp", "lldp", "discovery", "network", "cisco"],
        "references": [
            "https://attack.mitre.org/techniques/T1016/",
            "Cisco CDP",
            "IEEE 802.1AB LLDP",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016"],
            "prerequisites": [
                "Layer-2 access to the target switched network",
                "Root or CAP_NET_RAW on the capture interface",
                "CDP and/or LLDP enabled on adjacent switch ports",
            ],
            "detections": [
                "Passive monitoring of CDP/LLDP multicast frames",
            ],
            "artifacts": [
                "Local capture logs only",
            ],
        },
        "agent": {
            "risk": "passive",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.3,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "vlan_segment", "from_detail": "native_vlan"},
                    {"capability": "vlan_segment", "from_detail": "voice_vlan"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/vlan/id_scan",
                    "auxiliary/admin/vlan/dtp_trunk_negotiation",
                    "auxiliary/admin/vlan/double_tag_hop",
                ],
            },
        },
    }

    listen_cdp = OptBool(True, "Capture Cisco CDP frames", required=False)
    listen_lldp = OptBool(True, "Capture IEEE 802.1AB LLDP frames", required=False)
    output_file = OptString("", "Optional JSON output path", required=False)

    def check(self):
        if not self.vlan_require_scapy():
            print_error("scapy is not installed. Install it with: pip install scapy")
            return False
        if not self._iface():
            print_error("Interface is required")
            return False
        if not bool(self.listen_cdp) and not bool(self.listen_lldp):
            print_error("Enable LISTEN_CDP and/or LISTEN_LLDP")
            return False
        return True

    def run(self):
        iface = self._iface() or "eth0"
        timeout = self._cdp_timeout()
        listen_cdp = bool(self.listen_cdp)
        listen_lldp = bool(self.listen_lldp)

        print_info(f"CDP/LLDP neighbor enumeration on {iface} for {timeout:.1f}s")
        print_info(f"CDP: {'on' if listen_cdp else 'off'} | LLDP: {'on' if listen_lldp else 'off'}")
        print_info("=" * 72)

        try:
            data = self.vlan_enum_l2_neighbors(
                iface=iface,
                timeout=timeout,
                listen_cdp=listen_cdp,
                listen_lldp=listen_lldp,
            )
        except PermissionError:
            print_error(f"Permission denied on {iface} — run as root or grant CAP_NET_RAW")
            return False
        except OSError as exc:
            print_error(f"Capture failed on {iface}: {exc}")
            return False

        cdp_neighbors = data["cdp_neighbors"]
        lldp_neighbors = data["lldp_neighbors"]

        if cdp_neighbors:
            print_success(f"CDP neighbors: {len(cdp_neighbors)}")
            for hint in cdp_neighbors:
                parts = [hint.source_mac]
                if hint.device_id:
                    parts.append(hint.device_id)
                if hint.platform:
                    parts.append(hint.platform)
                if hint.port_id:
                    parts.append(f"port={hint.port_id}")
                if hint.native_vlan is not None:
                    parts.append(f"native_vlan={hint.native_vlan}")
                if hint.voice_vlan is not None:
                    parts.append(f"voice_vlan={hint.voice_vlan}")
                if hint.ip_address:
                    parts.append(f"ip={hint.ip_address}")
                if hint.capabilities:
                    parts.append(f"caps={hint.capabilities}")
                print_info("  " + " | ".join(parts))
        elif listen_cdp:
            print_info("No CDP neighbors observed")

        if lldp_neighbors:
            print_success(f"LLDP neighbors: {len(lldp_neighbors)}")
            for item in lldp_neighbors:
                parts = [item.source_mac]
                if item.system_name:
                    parts.append(item.system_name)
                if item.chassis_id:
                    parts.append(f"chassis={item.chassis_id}")
                if item.port_id:
                    parts.append(f"port={item.port_id}")
                if item.port_vlan_id is not None:
                    parts.append(f"port_vlan={item.port_vlan_id}")
                if item.vlan_name:
                    parts.append(f"vlan_name={item.vlan_name}")
                if item.management_address:
                    parts.append(f"mgmt={item.management_address}")
                print_info("  " + " | ".join(parts))
        elif listen_lldp:
            print_info("No LLDP neighbors observed")

        payload = {
            "interface": iface,
            "cdp_neighbors": self.vlan_cdp_to_dict(cdp_neighbors),
            "lldp_neighbors": self.vlan_lldp_to_dict(lldp_neighbors),
        }

        print_info("=" * 72)
        found = bool(cdp_neighbors or lldp_neighbors)
        if found:
            print_success("Layer-2 neighbor enumeration complete")
        else:
            print_warning("No CDP/LLDP neighbors captured — check interface and timeout")

        output_file = str(self.output_file or "").strip()
        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                print_success(f"Results saved to {output_file}")
            except OSError as exc:
                print_warning(f"Could not write output file: {exc}")

        return found
