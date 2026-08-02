#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""RTSP interleaved stream probe — SETUP/PLAY and drain a few RTP bytes."""

from kittysploit import *
from lib.protocols.rtsp.client import RTSP_PORT
from lib.protocols.rtsp.session import RtspSessionMixin


class Module(Post, RtspSessionMixin):
    __info__ = {
        "name": "RTSP stream probe",
        "description": (
            "DESCRIBE → SETUP (RTP/AVP/TCP interleaved) → PLAY and drain a short "
            "sample to confirm media delivery (session preferred)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.RTSP, SessionType.SHELL],
        "tags": ["iot", "camera", "rtsp", "gather", "stream"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["rtsp_access", "ot_assets"],
                "consumes_capabilities": ["rtsp_access"],
                "suggested_followups": [],
            },
            "requires": {"capabilities_any": ["rtsp_access", "ot_assets"]},
        },
    }

    session_id = OptString("", "RTSP session ID", False)
    rhost = OptString("", "Camera host when not using a session", False)
    rport = OptPort(RTSP_PORT, "RTSP port", False)
    path = OptString("/", "RTSP path", False)
    url = OptString("", "Full rtsp:// URL", False)
    username = OptString("", "Username", False)
    password = OptString("", "Password", False)

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
        except Exception as exc:
            print_error(str(exc))
            return False

        print_status(f"Opening interleaved stream on {client.request_uri}")
        result = client.open_stream_tcp(prefer_video=True)
        if result.get("error") and not result.get("play_ok"):
            print_error(str(result.get("error")))
            return False
        print_success(
            f"PLAY ok track={result.get('track') or '-'} "
            f"drained={result.get('bytes_drained')} bytes"
        )
        if result.get("transport"):
            print_info(f"  transport: {result['transport']}")
        if int(result.get("bytes_drained") or 0) == 0:
            print_warning("No interleaved bytes received (camera may require UDP or auth)")
        try:
            client.teardown()
        except Exception:
            pass
        return True
