#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Read ONVIF PTZ status for the first (or selected) media profile."""

from kittysploit import *
from lib.protocols.onvif.session import OnvifSessionMixin
import json
import os
import time


class Module(Post, OnvifSessionMixin):
    __info__ = {
        "name": "ONVIF PTZ Status",
        "description": (
            "Query ONVIF PTZ GetStatus for a media profile (pan/tilt/zoom). "
            "Uses an ONVIF session or rhost."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.ONVIF],
        "tags": ["iot", "camera", "onvif", "ptz", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints"],
            "chain": {
                "produces_capabilities": ["onvif_access"],
                "consumes_capabilities": ["onvif_access"],
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
    profile_token = OptString("", "Media profile token (auto if empty)", False)
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

        token = str(self.profile_token or "").strip()
        if not token:
            profiles = client.get_profiles()
            if not profiles:
                print_error("No media profiles found")
                return False
            token = profiles[0]
            print_info(f"Using profile token: {token}")

        if not client.ptz_xaddr:
            print_warning("No PTZ XAddr from capabilities — trying default ptz_service path")

        status = client.get_ptz_status(token)
        if not status.get("ok"):
            print_error(client.last_error or "PTZ GetStatus failed")
            return False

        print_success(
            f"PTZ pan={status.get('pan') or '?'} "
            f"tilt={status.get('tilt') or '?'} zoom={status.get('zoom') or '?'}"
        )
        result = {
            "host": client.host,
            "port": client.port,
            "ptz_xaddr": client.ptz_xaddr,
            "profile_token": token,
            "status": {k: v for k, v in status.items() if k != "raw"},
        }
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"onvif_ptz_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            print_success(f"Saved ./{path}")
        return True
