#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Dump IGD external IP and port mappings via UPnP WANIP/WANPPP actions."""

from kittysploit import *
from lib.protocols.upnp.client import SSDP_PORT
from lib.protocols.upnp.session import UpnpSessionMixin
import json
import os
import time


class Module(Post, UpnpSessionMixin):
    __info__ = {
        "name": "UPnP IGD Port Map Dump",
        "description": (
            "Call IGD GetExternalIPAddress / GetStatusInfo / GetGenericPortMappingEntry "
            "to inventory NAT port forwards exposed by the gateway."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.UPNP],
        "tags": ["iot", "upnp", "igd", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "chain": {
                "produces_capabilities": ["upnp_access", "ot_assets"],
                "consumes_capabilities": ["upnp_access"],
            },
            "requires": {"capabilities_any": ["upnp_access"]},
        },
    }

    session_id = OptString("", "UPnP session ID (optional if rhost/location set)", False)
    rhost = OptString("", "Host for SSDP when not using a session", False)
    rport = OptPort(SSDP_PORT, "SSDP UDP port", False)
    location = OptString("", "Device description URL (optional)", False)
    max_entries = OptInteger(64, "Max port mapping entries to enumerate", False)
    save_local = OptBool(True, "Save JSON under ./output", False)

    def check(self):
        if self._resolve_session():
            return True
        if str(self.rhost or "").strip() or str(self.location or "").strip():
            return True
        print_error("UPnP session_id, rhost, or location is required")
        return False

    def run(self):
        if not self.check():
            return False
        try:
            client = self.open_upnp()
        except Exception as exc:
            print_error(str(exc))
            return False

        wan = client.find_wan_service()
        if not wan:
            print_error("No WANIPConnection/WANPPPConnection service found")
            return False
        print_success(f"WAN service: {wan.service_type}")

        ext_ip = client.get_external_ip(wan)
        if ext_ip:
            print_success(f"External IP: {ext_ip}")
        else:
            print_warning(client.last_error or "GetExternalIPAddress failed")

        status = client.get_status_info(wan)
        if status:
            print_info(
                f"Status: {status.get('NewConnectionStatus') or status.get('ConnectionStatus') or status}"
            )

        mappings = client.get_port_mappings(wan, max_entries=int(self.max_entries or 64))
        print_status(f"{len(mappings)} port mapping(s)")
        for i, m in enumerate(mappings[:40], 1):
            proto = m.get("NewProtocol") or "?"
            eport = m.get("NewExternalPort") or "?"
            ihost = m.get("NewInternalClient") or "?"
            iport = m.get("NewInternalPort") or "?"
            desc = m.get("NewPortMappingDescription") or ""
            print_info(f"  [{i}] {proto} {eport} -> {ihost}:{iport} {desc}")

        result = {
            "host": client.host,
            "location": client.location,
            "wan_service": wan.service_type,
            "external_ip": ext_ip,
            "status": status,
            "mappings": mappings,
        }
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"upnp_igd_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            print_success(f"Saved ./{path}")
        return True
