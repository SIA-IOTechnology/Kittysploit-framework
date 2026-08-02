#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect mDNS / DNS-SD responders and map IoT service types to modules."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.mdns.session import MdnsProbeMixin


class Module(Scanner, Ics_scanner_client, MdnsProbeMixin):
    __info__ = {
        "name": "mDNS / DNS-SD Detection",
        "description": (
            "Queries DNS-SD over unicast or multicast mDNS (UDP 5353). In typed mode, "
            "probes IoT service types and suggests KittySploit follow-up modules."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["mdns", "dns-sd", "zeroconf", "iot", "udp", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "chain": {
                "produces_capabilities": ["ot_assets"],
                "suggested_followups": [
                    "scanner/udp/mdns_enum",
                    "scanner/udp/matter_detect",
                    "workflow/iot-discovery",
                    "listeners/iot/mqtt",
                    "listeners/iot/coap_client",
                    "listeners/iot/onvif_client",
                    "listeners/iot/rtsp_client",
                    "listeners/iot/matter_client",
                    "listeners/iot/upnp_client",
                ],
            },
        },
    }

    port = OptPort(5353, "mDNS UDP port", True)
    typed = OptBool(
        True,
        "Probe common IoT service types (_mqtt/_coap/_onvif/…) and suggest modules",
        False,
    )
    multicast = OptBool(False, "Also browse multicast 224.0.0.251", False)

    def run(self):
        host = self._host()
        if not host and not bool(self.multicast):
            return False

        if bool(self.typed):
            result = self.enumerate_mdns(
                host=host or "",
                multicast=bool(self.multicast),
                resolve_srv=False,
                timeout=self._timeout(),
            )
            info = self.mdns_result_as_dict(result)
            services = list(info.get("names") or [])[:16]
            suggested = list(info.get("suggested_modules") or [])[:8]
            detected = bool(info.get("detected"))
        else:
            from lib.scanner.mdns.detectors import probe_mdns

            info = probe_mdns(host=host, port=self._port(), timeout=self._timeout())
            services = list(info.get("services") or [])[:16]
            suggested = []
            detected = bool(info.get("detected"))

        if not detected:
            return False

        self.set_info(
            severity="info",
            reason="mDNS responder detected",
            services=services,
            suggested_modules=suggested,
        )
        if suggested:
            print_status("Suggested follow-ups:")
            for module in suggested:
                print_info(f"  → {module}")
            print_info("Deeper enum: scanner/udp/mdns_enum")
        return True
