#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Enumerate ONVIF media profiles, snapshot URIs, and RTSP stream URIs."""

from kittysploit import *
from lib.protocols.onvif.session import OnvifSessionMixin
import json
import os
import time


class Module(Post, OnvifSessionMixin):
    __info__ = {
        "name": "ONVIF Media Streams",
        "description": (
            "List ONVIF media profiles and resolve GetSnapshotUri + GetStreamUri "
            "(RTSP) for RTSP handoff. Uses an ONVIF session or rhost."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.ONVIF],
        "tags": ["iot", "camera", "onvif", "rtsp", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["onvif_access", "ot_assets"],
                "consumes_capabilities": ["onvif_access"],
                "suggested_followups": [
                    "listeners/iot/rtsp_client",
                    "post/rtsp/gather/describe_dump",
                    "auxiliary/admin/http/camera/onvif_snapshot",
                ],
            },
            "requires": {"capabilities_any": ["onvif_access"]},
        },
    }

    session_id = OptString("", "ONVIF session ID (optional if rhost set)", False)
    rhost = OptString("", "Camera host when not using a session", False)
    rport = OptPort(80, "HTTP port", False)
    ssl = OptBool(False, "Use HTTPS", False)
    username = OptString("", "ONVIF username", False)
    password = OptString("", "ONVIF password", False)
    save_local = OptBool(True, "Save JSON under ./output", False)

    def check(self):
        if self._resolve_session():
            return True
        if str(self.rhost or "").strip():
            return True
        print_error("ONVIF session_id or rhost is required")
        return False

    def run(self):
        if not self.check():
            return False
        try:
            client = self.open_onvif(discover=True)
        except Exception as exc:
            print_error(str(exc))
            return False

        print_status(f"Media enum on {client.host}:{client.port}")
        profiles = client.get_profiles_detail()
        if not profiles:
            print_error("No media profiles found (auth required?)")
            return False

        streams = []
        for prof in profiles:
            token = prof["token"]
            snap = client.get_snapshot_uri(token)
            rtsp = client.get_stream_uri(token, protocol="RTSP")
            entry = {
                "token": token,
                "name": prof.get("name") or "",
                "snapshot_uri": snap,
                "stream_uri": rtsp,
            }
            streams.append(entry)
            print_success(f"Profile {token} ({entry['name'] or '-'})")
            if snap:
                print_info(f"  snapshot: {snap}")
            if rtsp:
                print_info(f"  rtsp: {rtsp}")

        result = {
            "host": client.host,
            "port": client.port,
            "media_xaddr": client.media_xaddr,
            "profiles": streams,
        }
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"onvif_media_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            print_success(f"Saved ./{path}")
        return True
