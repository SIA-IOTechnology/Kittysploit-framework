#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""RTSP DESCRIBE dump — SDP media inventory via session or URL."""

from kittysploit import *
from lib.protocols.rtsp.client import RTSP_PORT, probe_rtsp
from lib.protocols.rtsp.session import RtspSessionMixin
import json
import os
import time


class Module(Post, RtspSessionMixin):
    __info__ = {
        "name": "RTSP describe dump",
        "description": "OPTIONS + DESCRIBE against an RTSP URL/session and dump SDP media tracks",
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.RTSP, SessionType.SHELL],
        "tags": ["iot", "camera", "rtsp", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["rtsp_access", "ot_assets"],
                "consumes_capabilities": [],
                "suggested_followups": [
                    "post/rtsp/gather/stream_probe",
                    "listeners/iot/rtsp_client",
                ],
            },
            "requires": {"capabilities_any": ["rtsp_access", "ot_assets", "onvif_access"]},
        },
    }

    session_id = OptString("", "RTSP session ID", False)
    rhost = OptString("", "Camera host when not using a session", False)
    rport = OptPort(RTSP_PORT, "RTSP port", False)
    path = OptString("/", "RTSP path", False)
    url = OptString("", "Full rtsp:// URL", False)
    username = OptString("", "Username", False)
    password = OptString("", "Password", False)
    save_local = OptBool(True, "Save JSON under ./output", False)

    def check(self):
        if self._resolve_session():
            return True
        if str(self.url or "").strip() or str(self.rhost or "").strip():
            return True
        print_error("RTSP session_id, url, or rhost is required")
        return False

    def run(self):
        if not self.check():
            return False
        try:
            client = self.open_rtsp(connect=True)
            info = client.probe()
        except Exception:
            host = str(self.rhost or "").strip()
            url = str(self.url or "").strip()
            if not host and not url:
                print_error("RTSP session or target is required")
                return False
            info = probe_rtsp(
                host,
                int(self.rport or RTSP_PORT),
                str(self.path or "/"),
                str(self.username or ""),
                str(self.password or ""),
                float(self.timeout or 5),
                url=url,
            )

        if info.get("error") and not info.get("media"):
            print_error(str(info.get("error")))
            if info.get("auth_required"):
                print_warning("Authentication required — set username/password")
            return False

        media = info.get("media") or []
        print_success(f"RTSP {info.get('url')} — {len(media)} track(s)")
        if info.get("server"):
            print_info(f"  server: {info['server']}")
        if info.get("options"):
            print_info(f"  options: {', '.join(info['options'])}")
        for item in media:
            print_info(
                f"  {item.get('type')} enc={item.get('encoding') or '?'} "
                f"control={item.get('control') or '-'}"
            )
        if info.get("auth_required"):
            print_warning("Endpoint advertised authentication requirement")

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"rtsp_describe_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(info, fh, indent=2)
            print_success(f"Saved {path}")
        return True
