#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Fetch an ONVIF snapshot JPEG via GetSnapshotUri."""

from kittysploit import *
from lib.protocols.onvif.session import OnvifSessionMixin
import os
import time


class Module(Auxiliary, OnvifSessionMixin):
    __info__ = {
        "name": "ONVIF Snapshot Grab",
        "description": (
            "Authenticate to ONVIF Media service, resolve GetSnapshotUri for the "
            "first profile, and download a JPEG snapshot. Prefers an ONVIF session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.ONVIF],
        "tags": ["iot", "camera", "onvif", "gather"],
        "references": ["https://www.onvif.org/"],
        "agent": {
            "risk": "intrusive",
            "effects": ["reconnaissance"],
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["onvif_access"],
                "produces_capabilities": ["file_read", "onvif_access"],
            },
            "requires": {"capabilities_any": ["onvif_access"]},
        },
    }

    session_id = OptString("", "ONVIF session ID (optional if rhost set)", False)
    rhost = OptString("", "Camera host", False)
    rport = OptPort(80, "HTTP port", False)
    ssl = OptBool(False, "Use HTTPS", False)
    username = OptString("admin", "ONVIF username", False)
    password = OptString("admin", "ONVIF password", False)
    profile_token = OptString("", "Media profile token (auto if empty)", False)
    save_local = OptBool(True, "Save JPEG under ./output", False)

    def run(self):
        try:
            client = self.open_onvif(discover=True)
        except Exception as exc:
            print_error(str(exc))
            return False

        print_status(f"ONVIF snapshot on {client.host}:{client.port}...")
        client.get_capabilities()
        token = str(self.profile_token or "").strip()
        if not token:
            profiles = client.get_profiles()
            if not profiles:
                print_error("No media profiles found (auth required?)")
                return False
            token = profiles[0]
            print_info(f"Using profile token: {token}")

        uri = client.get_snapshot_uri(token)
        if not uri:
            print_error(client.last_error or "GetSnapshotUri failed")
            return False
        print_success(f"Snapshot URI: {uri}")

        try:
            data = client.download_uri(uri)
        except Exception as exc:
            print_error(f"Download failed: {exc}")
            return False

        if not data or len(data) < 100:
            print_error("Snapshot payload empty/too small")
            return False

        print_success(f"Downloaded {len(data)} bytes")
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"onvif_snapshot_{stamp}.jpg")
            with open(path, "wb") as fh:
                fh.write(data)
            print_success(f"Saved ./{path}")
        return True
