#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Discover active VLAN IDs from an access port using tagged DHCP/ARP probes."""

from __future__ import annotations

import json
from typing import List

from kittysploit import *
from lib.protocols.vlan.vlan_client import Vlan_client


class Module(Auxiliary, Vlan_client):
    __info__ = {
        "name": "VLAN ID Scanner",
        "description": (
            "Hop through 802.1Q VLAN IDs on a Layer-2 access port by sending tagged "
            "DHCP and ARP probes, optionally harvesting CDP native VLAN hints first."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "vlan", "802.1q", "dot1q", "discovery", "network"],
        "references": [
            "https://attack.mitre.org/techniques/T1016/",
            "IEEE 802.1Q",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016"],
            "prerequisites": [
                "Layer-2 access to the target switched network",
                "Ethernet interface with raw frame injection (CAP_NET_RAW / root)",
                "Authorized assessment scope",
            ],
            "detections": [
                "Tagged DHCP/ARP probes across many VLAN IDs",
                "Switch port anomaly / VLAN hopping heuristics",
            ],
            "artifacts": [
                "Switch CAM table updates",
                "DHCP server logs on discovered VLANs",
            ],
        },
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "cost": 1.5,
            "noise": 0.7,
            "value": 1.2,
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
                "produces_capabilities": [{"capability": "vlan_segment", "from_detail": "vlan_id"}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/vlan/cdp_lldp_enum",
                    "auxiliary/admin/vlan/dtp_trunk_negotiation",
                    "auxiliary/admin/vlan/double_tag_hop",
                ],
            },
        },
    }

    vlan_start = OptInteger(1, "First VLAN ID when scanning a range", required=False)
    vlan_end = OptInteger(256, "Last VLAN ID when scanning a range", required=False)
    vlan_list = OptString(
        "",
        "Explicit VLAN list/ranges (e.g. 10,20,100-120). Overrides VLAN_START/VLAN_END",
        required=False,
    )
    methods = OptChoice(
        "dhcp,arp",
        "Probe methods (comma-separated: dhcp, arp)",
        required=False,
        choices=["dhcp", "arp", "dhcp,arp", "arp,dhcp"],
    )
    probe_ip = OptString(
        "255.255.255.255",
        "Target IPv4 for ARP probes (broadcast or .1 gateway)",
        required=False,
    )
    per_vlan_timeout = OptFloat(
        0.8,
        "Seconds to wait for a response on each VLAN ID",
        required=False,
    )
    output_file = OptString("", "Optional JSON output path", required=False)

    def check(self):
        if not self.vlan_require_scapy():
            print_error("scapy is not installed. Install it with: pip install scapy")
            return False

        iface = self._iface()
        if not iface:
            print_error("Interface is required")
            return False

        try:
            self.vlan_interface_mac(iface)
        except Exception as exc:
            print_error(f"Could not resolve MAC for {iface}: {exc}")
            return False
        return True

    def _method_list(self) -> List[str]:
        raw = str(self.methods or "dhcp,arp").replace(" ", "")
        values = [item.strip().lower() for item in raw.split(",") if item.strip()]
        return values or ["dhcp", "arp"]

    def run(self):
        iface = self._iface() or "eth0"
        methods = self._method_list()
        vlan_ids = list(
            self.vlan_iter_ids(
                int(self.vlan_start or 1),
                int(self.vlan_end or 256),
                str(self.vlan_list or ""),
            )
        )
        probe_ip = str(self.probe_ip or "255.255.255.255").strip()
        per_vlan_timeout = max(0.2, float(self.per_vlan_timeout or 0.8))

        print_info(f"VLAN ID scan on {iface} across {len(vlan_ids)} VLAN ID(s)")
        print_info(f"Methods: {', '.join(methods)}")
        print_info("=" * 72)

        try:
            client_mac = self.vlan_interface_mac(iface)
        except Exception as exc:
            print_error(str(exc))
            return False

        print_info(f"Source MAC: {client_mac}")

        cdp_timeout = self._cdp_timeout()
        native_hints = []
        if cdp_timeout > 0:
            print_status(f"Listening {cdp_timeout:.1f}s for CDP native VLAN hints...")
            try:
                hints = self.vlan_sniff_cdp(iface=iface, timeout=cdp_timeout)
            except PermissionError:
                print_error(f"Permission denied on {iface} — run as root or grant CAP_NET_RAW")
                return False
            except OSError as exc:
                print_error(f"CDP capture failed on {iface}: {exc}")
                return False

            native_hints = self.vlan_cdp_to_dict(hints)
            for hint in hints:
                parts = [hint.source_mac]
                if hint.device_id:
                    parts.append(hint.device_id)
                if hint.native_vlan is not None:
                    parts.append(f"native_vlan={hint.native_vlan}")
                print_success("CDP: " + " | ".join(parts))

            if not hints:
                print_info("No CDP hints observed (non-Cisco edge or CDP disabled)")

        def _progress(current: int, total: int) -> None:
            if current == 1 or current == total or current % 25 == 0:
                print_status(f"Progress: {current}/{total} VLAN IDs probed")

        print_status("Starting tagged VLAN probes...")
        try:
            hits = self.vlan_scan_ids(
                vlan_ids=vlan_ids,
                methods=methods,
                probe_ip=probe_ip,
                per_vlan_timeout=per_vlan_timeout,
                iface=iface,
                client_mac=client_mac,
                progress=_progress,
            )
        except PermissionError:
            print_error(f"Permission denied on {iface} — run as root or grant CAP_NET_RAW")
            return False
        except OSError as exc:
            print_error(f"VLAN probe failed on {iface}: {exc}")
            return False

        print_info("=" * 72)
        payload = {
            "interface": iface,
            "methods": methods,
            "probe_ip": probe_ip,
            "cdp_hints": native_hints,
            "active_vlans": [
                {
                    "vlan_id": hit.vlan_id,
                    "method": hit.method,
                    "detail": hit.detail,
                    "source": hit.source,
                }
                for hit in hits
            ],
        }

        if hits:
            print_success(f"Discovered {len(hits)} active VLAN ID(s)")
            for hit in hits:
                detail = f" | {hit.detail}" if hit.detail else ""
                source = f" | from {hit.source}" if hit.source else ""
                print_info(f"  VLAN {hit.vlan_id:4d} via {hit.method}{detail}{source}")
        else:
            print_warning("No active VLAN IDs detected with current methods/timeouts")
            print_info("Try widening VLAN_END, increasing PER_VLAN_TIMEOUT, or adding ARP against x.x.x.1")

        output_file = str(self.output_file or "").strip()
        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                print_success(f"Results saved to {output_file}")
            except OSError as exc:
                print_warning(f"Could not write output file: {exc}")

        return bool(hits)
