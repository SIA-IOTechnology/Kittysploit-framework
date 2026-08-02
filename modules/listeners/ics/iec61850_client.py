#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""IEC 61850 MMS bind listener — opens an MMS session for identify / directory."""

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.iec61850_client import Iec61850Client


class Module(Listener):
    __info__ = {
        "name": "IEC 61850 MMS Client",
        "description": (
            "Connects to an IEC 61850 MMS server (ISO-on-TCP), completes COTP + Initiate, "
            "and creates an interactive MMS shell session."
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.IEC61850,
        "protocol": "iec61850",
        "tags": ["ics", "iec61850", "mms", "substation"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["ot_assets", "iec61850"],
                "suggested_followups": [
                    "post/ics/iec61850/gather/identify",
                    "post/ics/iec61850/gather/directory_dump",
                ],
            },
        },
    }

    rhost = OptString("127.0.0.1", "Target MMS host", True)
    rport = OptPort(ICS_PROTOCOL_PORTS.get("iec61850", 102), "ISO-on-TCP port", True)
    skip_s7_check = OptBool(False, "Skip S7comm conflict probe", False)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport or 102)
        timeout = float(self.timeout or 5)

        print_status(f"Connecting to IEC 61850 MMS {host}:{port}...")
        client = Iec61850Client(host, port, timeout)
        if not client.connect(check_s7=not bool(self.skip_s7_check)):
            print_error(client.last_error or f"MMS connection failed for {host}:{port}")
            return False

        print_success(
            f"COTP accepted initiate_ok={client.initiate_ok}"
        )
        if client.last_strings:
            print_info(f"  strings: {', '.join(client.last_strings[:6])}")

        additional_data = {
            "host": host,
            "port": port,
            "protocol": "iec61850",
            "platform": "ics",
            "timeout": timeout,
            "initiate_ok": client.initiate_ok,
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
