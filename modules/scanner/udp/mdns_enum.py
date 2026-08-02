#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep mDNS / DNS-SD enumeration with SRV/TXT/A correlation and module handoff."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.mdns.session import MdnsProbeMixin
import json
import os
import time


class Module(Scanner, Ics_scanner_client, MdnsProbeMixin):
    __info__ = {
        "name": "mDNS / DNS-SD Enum",
        "description": (
            "Enumerates DNS-SD instances via unicast or multicast mDNS, resolves "
            "PTR→SRV/TXT/A, and suggests KittySploit protocol sessions."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["mdns", "dns-sd", "zeroconf", "iot", "udp", "scanner", "discovery", "enum"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["ot_assets", "mdns_map"],
                "suggested_followups": [
                    "listeners/iot/mqtt",
                    "listeners/iot/coap_client",
                    "listeners/iot/onvif_client",
                    "listeners/iot/rtsp_client",
                    "listeners/iot/upnp_client",
                    "workflow/iot-discovery",
                ],
            },
        },
    }

    port = OptPort(5353, "mDNS UDP port", True)
    multicast = OptBool(
        False,
        "Browse 224.0.0.251 (LAN-wide) instead of unicast to target",
        False,
    )
    resolve_srv = OptBool(True, "Follow PTR with SRV/TXT/ANY queries", False)
    save_local = OptBool(True, "Save JSON inventory under ./output", False)

    def run(self):
        host = self._host()
        use_mcast = bool(self.multicast) or not host
        if not use_mcast and not host:
            print_error("Target required for unicast mode (or set multicast=true)")
            return False

        print_status(
            f"mDNS enum mode={'multicast' if use_mcast else 'unicast'} "
            f"host={host or '*'} port={self._port()}"
        )
        result = self.enumerate_mdns(
            host=host or "",
            multicast=use_mcast,
            resolve_srv=bool(self.resolve_srv),
            timeout=self._timeout(),
        )
        payload = self.mdns_result_as_dict(result)
        if not result.detected:
            print_error(result.error or "No mDNS services")
            return False

        print_success(
            f"Found {len(result.services)} instance(s), "
            f"{len(result.suggested_modules)} follow-up module(s)"
        )
        for svc in result.services[:20]:
            addr = ",".join(svc.addresses[:2]) or "-"
            print_info(
                f"  {svc.service_type or '?'}  {svc.instance}  "
                f"{svc.host or '-'}:{svc.port or '-'}  [{addr}]"
            )
            if svc.txt:
                preview = ", ".join(f"{k}={v}" for k, v in list(svc.txt.items())[:4])
                print_info(f"    txt: {preview}")

        if result.suggested_modules:
            print_status("Suggested follow-ups:")
            for module in result.suggested_modules:
                print_info(f"  → {module}")

        self.set_info(
            severity="info",
            reason="mDNS services enumerated",
            services=payload.get("names") or [],
            mdns_services=payload.get("services") or [],
            suggested_modules=result.suggested_modules,
        )

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"mdns_enum_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            print_success(f"Saved {path}")
        return True
