#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""IEC 61850 MMS directory dump — Identify + GetNameList domains/variables."""

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.iec61850_client import directory_iec61850
from lib.protocols.ics.ics_session_mixin import Iec61850SessionMixin
import json
import os
import time


class Module(Post, Ics_scanner_client, Iec61850SessionMixin):
    __info__ = {
        "name": "IEC 61850 MMS directory dump",
        "description": (
            "MMS Identify plus GetNameList for domains and named variables "
            "(session preferred)."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "iec61850", "mms", "substation", "gather"],
        "session_type": [SessionType.IEC61850, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "iec61850", "from_detail": ""},
                    {"capability": "ot_assets", "from_detail": ""},
                ],
                "suggested_followups": [
                    "post/ics/iec61850/gather/identify",
                ],
            },
            "requires": {"capabilities_any": ["ot_assets", "iec61850"]},
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS.get("iec61850", 102), "ISO-on-TCP port", True)
    save_local = OptBool(True, "Save JSON under ./output", False)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        try:
            client = self.open_iec61850()
            result = client.directory(keep_open=True)
        except Exception:
            host = self._host()
            if not host:
                print_error("IEC 61850 session or target is required")
                return False
            result = directory_iec61850(host, self._port(), self._timeout())

        if result.error and not (result.strings or result.domains or result.variables):
            print_error(result.error)
            return False

        print_success(
            f"Directory on {result.host}:{result.port} — "
            f"domains={len(result.domains)} vars={len(result.variables)}"
        )
        if result.vendor or result.model:
            print_info(f"  identify: {result.vendor} / {result.model} / {result.revision}")
        for d in result.domains[:16]:
            print_info(f"  domain: {d}")
        for v in result.variables[:16]:
            print_info(f"  var: {v}")

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"iec61850_directory_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "host": result.host,
                        "port": result.port,
                        "vendor": result.vendor,
                        "model": result.model,
                        "revision": result.revision,
                        "strings": result.strings,
                        "domains": result.domains,
                        "variables": result.variables,
                    },
                    fh,
                    indent=2,
                )
            print_success(f"Saved {path}")

        self.sync_workspace_ics(
            port=result.port,
            protocol="iec61850",
            device_type="IED/MMS",
            purdue_level=1,
            source="post/ics/iec61850/gather/directory_dump",
        )
        return True
