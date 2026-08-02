#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ONVIF bind listener — opens an interactive ONVIF camera session."""

from kittysploit import *
from lib.protocols.onvif.client import OnvifClient


class Module(Listener):
    __info__ = {
        "name": "ONVIF Client",
        "description": (
            "Discovers an ONVIF device service, loads Media/PTZ/Events capabilities, "
            "and creates an interactive ONVIF shell session."
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.ONVIF,
        "protocol": "onvif",
        "tags": ["iot", "camera", "onvif"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["onvif_access", "ot_assets"],
                "suggested_followups": [
                    "post/onvif/gather/media_streams",
                    "post/onvif/gather/ptz_status",
                    "auxiliary/admin/http/camera/onvif_snapshot",
                    "listeners/iot/rtsp_client",
                ],
            },
        },
    }

    rhost = OptString("127.0.0.1", "Camera host", True)
    rport = OptPort(80, "HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", False)
    username = OptString("", "ONVIF username (optional)", False)
    password = OptString("", "ONVIF password (optional)", False)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport or 80)
        timeout = float(self.timeout or 8)
        use_https = bool(self.ssl)

        print_status(f"Probing ONVIF on {host}:{port}...")
        client = OnvifClient(
            host,
            port,
            str(self.username or ""),
            str(self.password or ""),
            use_https=use_https,
            timeout=timeout,
        )
        if not client.connect():
            print_error(client.last_error or "No ONVIF device service found")
            return False

        info = client.get_device_information()
        print_success(f"Device service: {client.device_path}")
        print_info(f"  {info.manufacturer or '?'} {info.model or '?'} fw={info.firmware or '?'}")
        if client.media_xaddr:
            print_success(f"Media: {client.media_xaddr}")
        if client.ptz_xaddr:
            print_success(f"PTZ: {client.ptz_xaddr}")
        if client.events_xaddr:
            print_success(f"Events: {client.events_xaddr}")

        additional_data = {
            "host": host,
            "port": port,
            "username": str(self.username or ""),
            "password": str(self.password or ""),
            "ssl": use_https,
            "use_https": use_https,
            "device_path": client.device_path,
            "media_xaddr": client.media_xaddr,
            "ptz_xaddr": client.ptz_xaddr,
            "events_xaddr": client.events_xaddr,
            "manufacturer": info.manufacturer,
            "model": info.model,
            "firmware": info.firmware,
            "protocol": "onvif",
            "platform": "iot",
            "timeout": timeout,
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
