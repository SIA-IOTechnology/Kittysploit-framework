#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""IEC 61850 MMS Identify via session or direct target."""

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.iec61850_client import identify_iec61850
from lib.protocols.ics.ics_session_mixin import Iec61850SessionMixin


class Module(Post, Ics_scanner_client, Iec61850SessionMixin):
    __info__ = {
        "name": "IEC 61850 MMS identify",
        "description": "MMS Identify request — extract vendor/model/revision strings (session preferred)",
        "author": "KittySploit Team",
        "tags": ["ics", "iec61850", "mms", "substation", "gather"],
        "session_type": [SessionType.IEC61850, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "iec61850", "from_detail": ""},
                    {"capability": "ot_assets", "from_detail": ""},
                ],
                "suggested_followups": [
                    "post/ics/iec61850/gather/directory_dump",
                    "listeners/ics/iec61850_client",
                ],
            },
            "requires": {"capabilities_any": ["ot_assets", "iec61850"]},
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS.get("iec61850", 102), "ISO-on-TCP port", True)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        try:
            client = self.open_iec61850()
            result = client.identify(keep_open=True)
        except Exception:
            host = self._host()
            if not host:
                print_error("IEC 61850 session or target is required")
                return False
            result = identify_iec61850(host, self._port(), self._timeout())

        if result.error and not result.strings:
            print_error(result.error)
            return False
        print_success(
            f"MMS Identify on {result.host}:{result.port} "
            f"vendor={result.vendor or '-'} model={result.model or '-'}"
        )
        if result.revision:
            print_info(f"  revision: {result.revision}")
        for s in result.strings[:12]:
            print_info(f"  {s}")
        self.sync_workspace_ics(
            port=result.port,
            protocol="iec61850",
            device_type="IED/MMS",
            purdue_level=1,
            source="post/ics/iec61850/gather/identify",
        )
        return True
