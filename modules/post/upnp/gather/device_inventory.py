#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Inventory UPnP device description and services."""

from kittysploit import *
from lib.protocols.upnp.client import SSDP_PORT
from lib.protocols.upnp.session import UpnpSessionMixin
import json
import os
import time


class Module(Post, UpnpSessionMixin):
    __info__ = {
        "name": "UPnP Device Inventory",
        "description": (
            "Dump UPnP device identity and service list from an SSDP session "
            "or direct LOCATION/rhost discover."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.UPNP],
        "tags": ["iot", "upnp", "ssdp", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["upnp_access", "ot_assets"],
                "consumes_capabilities": ["upnp_access"],
                "suggested_followups": ["post/upnp/gather/igd_portmap"],
            },
            "requires": {"capabilities_any": ["upnp_access"]},
        },
    }

    session_id = OptString("", "UPnP session ID (optional if rhost/location set)", False)
    rhost = OptString("", "Host for SSDP when not using a session", False)
    rport = OptPort(SSDP_PORT, "SSDP UDP port", False)
    location = OptString("", "Device description URL (optional)", False)
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

        inv = client.inventory()
        device = inv.get("device") or {}
        print_success(f"LOCATION: {inv.get('location')}")
        print_info(
            f"{device.get('friendly_name') or '?'} — "
            f"{device.get('manufacturer') or '?'} {device.get('model_name') or '?'}"
        )
        services = inv.get("services") or []
        print_status(f"{len(services)} service(s)")
        for svc in services[:40]:
            wan = " [WAN]" if svc.get("is_wan") else ""
            print_info(f"  {svc.get('service_type')}{wan}")

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"upnp_inventory_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(inv, fh, indent=2)
            print_success(f"Saved ./{path}")
        return True
