#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.iec104_client import dump_iec104_interrogation
from lib.protocols.ics.ics_session_mixin import Iec104SessionMixin


class Module(Post, Ics_scanner_client, Iec104SessionMixin):
    __info__ = {
        "name": "IEC104 interrogation dump",
        "description": "Collects IEC 60870-5-104 responses after a general interrogation (session preferred)",
        "author": "KittySploit Team",
        "tags": ["ics", "iec104", "utilities", "gather"],
        "session_type": [SessionType.IEC104, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {"capabilities_any": ["ot_assets", "iec104"]},
            "chain": {
                "produces_capabilities": [
                    {"capability": "ot_assets", "from_detail": ""},
                    {"capability": "iec104", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "suggested_followups": [
                    "post/ics/iec104/manage/single_command",
                    "post/ics/iec104/manage/double_command",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["iec104"], "IEC104 TCP port", True)
    common_address = OptInteger(1, "Common address (CA)", False)
    max_frames = OptInteger(16, "Maximum APDU frames to collect", False)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        max_frames = int(self.max_frames or 16)
        owns_client = False
        try:
            client = self.open_iec104()
            if int(self.common_address or 0):
                client.common_address = int(self.common_address)
            if not client.startdt():
                print_error("STARTDT not confirmed")
                return False
            if not client.general_interrogation():
                print_error("Interrogation send failed")
                return False
            frames = client.collect_frames(max_frames)
            host = client.host
        except Exception:
            host = self._host()
            if not host:
                print_error("IEC104 session or target is required")
                return False
            result = dump_iec104_interrogation(
                host,
                self._port(),
                self._timeout(),
                int(self.common_address or 1),
                max_frames,
            )
            if not result.connected or not result.startdt_confirmed:
                print_error(result.error or "Interrogation failed")
                return False
            frames = list(result.responses or [])

        print_success(f"Collected {len(frames)} IEC104 response frame(s) from {host}")
        for index, frame in enumerate(frames[:8], start=1):
            preview = frame[:120]
            print_info(f"  [{index}] {preview}{'...' if len(frame) > 120 else ''}")
        if not frames:
            print_warning("Interrogation completed — no response frames captured")
        return True
