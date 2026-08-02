#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""IEC 60870-5-104 bind listener — opens an IEC 104 session for interrogation."""

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.iec104_client import Iec104Client


class Module(Listener):
    __info__ = {
        "name": "IEC 60870-5-104 Client",
        "description": "Connects to an IEC 104 server and creates an interactive IEC 104 shell session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.IEC104,
        "protocol": "iec104",
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["ot_assets", "iec104"],
                "suggested_followups": ["post/ics/iec104/gather/interrogation_dump"],
            },
        },
    }

    rhost = OptString("127.0.0.1", "Target IEC 104 host", True)
    rport = OptPort(ICS_PROTOCOL_PORTS["iec104"], "IEC 104 TCP port", True)
    common_address = OptInteger(1, "ASDU common address", False)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport)
        ca = int(self.common_address or 1)
        timeout = float(self.timeout or 5)

        print_status(f"Connecting to IEC 104 {host}:{port} (CA={ca})...")
        client = Iec104Client(host, port, timeout, ca)
        if not client.connect():
            print_error(f"IEC 104 connection failed for {host}:{port}")
            return False

        if client.startdt():
            print_success("IEC 104 STARTDT confirmed")
        else:
            print_warning("Connected but STARTDT not confirmed — session may be limited")

        additional_data = {
            "host": host,
            "port": port,
            "common_address": ca,
            "protocol": "iec104",
            "platform": "ics",
            "timeout": timeout,
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
