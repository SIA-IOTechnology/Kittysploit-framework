#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ONVIF device information gather (HTTP SOAP)."""

from kittysploit import *
from lib.protocols.onvif.session import OnvifSessionMixin
import json
import os
import time


class Module(Auxiliary, OnvifSessionMixin):
    __info__ = {
        "name": "ONVIF Device Information",
        "description": (
            "Query an IP camera ONVIF device service for manufacturer/model/"
            "firmware and Media service XAddr. Prefers an ONVIF session when set."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.ONVIF],
        "tags": ["iot", "camera", "onvif", "gather"],
        "references": ["https://www.onvif.org/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["onvif_access", "ot_assets"],
                "suggested_followups": [
                    "listeners/iot/onvif_client",
                    "post/onvif/gather/media_streams",
                    "auxiliary/admin/http/camera/onvif_snapshot",
                ],
            },
        },
    }

    session_id = OptString("", "ONVIF session ID (optional if rhost set)", False)
    rhost = OptString("", "Camera host", False)
    rport = OptPort(80, "HTTP port", False)
    ssl = OptBool(False, "Use HTTPS", False)
    username = OptString("", "ONVIF username (optional)", False)
    password = OptString("", "ONVIF password (optional)", False)
    save_local = OptBool(True, "Save JSON under ./output", False)

    def run(self):
        try:
            client = self.open_onvif(discover=True)
        except Exception as exc:
            print_error(str(exc))
            return False

        print_status(f"Probing ONVIF on {client.host}:{client.port}...")
        print_success(f"Device service: {client.device_path}")
        info = client.get_device_information()
        client.get_capabilities()
        result = {
            "host": client.host,
            "port": client.port,
            "device_path": client.device_path,
            "manufacturer": info.manufacturer,
            "model": info.model,
            "firmware": info.firmware,
            "serial": info.serial,
            "hardware": info.hardware,
            "media_xaddr": client.media_xaddr,
            "ptz_xaddr": client.ptz_xaddr,
            "events_xaddr": client.events_xaddr,
        }
        print_info(f"Manufacturer: {info.manufacturer or '?'}")
        print_info(f"Model: {info.model or '?'}")
        print_info(f"Firmware: {info.firmware or '?'}")
        print_info(f"Serial: {info.serial or '?'}")
        if client.media_xaddr:
            print_success(f"Media XAddr: {client.media_xaddr}")
        if client.ptz_xaddr:
            print_success(f"PTZ XAddr: {client.ptz_xaddr}")
        if client.events_xaddr:
            print_success(f"Events XAddr: {client.events_xaddr}")

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"onvif_device_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            print_success(f"Saved ./{path}")
        return True
