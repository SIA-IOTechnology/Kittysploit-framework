#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""DNP3 TCP bind listener — opens a DNP3 session for interactive polling."""

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import Dnp3Client


class Module(Listener):
    __info__ = {
        "name": "DNP3 TCP Client",
        "description": "Connects to a DNP3 outstation and creates an interactive DNP3 shell session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.DNP3,
        "protocol": "dnp3",
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["ot_assets", "dnp3_access"],
                "suggested_followups": ["post/ics/dnp3/gather/read_points"],
            },
        },
    }

    rhost = OptString("127.0.0.1", "Target DNP3 host", True)
    rport = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)
    src = OptInteger(1024, "DNP3 master (source) address", False)
    dest = OptInteger(1, "DNP3 outstation (destination) address", False)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport)
        src = int(self.src or 1024)
        dest = int(self.dest or 1)
        timeout = float(self.timeout or 5)

        print_status(f"Connecting to DNP3 {host}:{port} (src={src} dest={dest})...")
        client = Dnp3Client(host, port, timeout, src, dest)
        if not client.connect():
            print_error(f"DNP3 TCP connection failed for {host}:{port}")
            return False

        identify = client.identify()
        if identify.error:
            print_warning(f"Connected but identify weak: {identify.error}")
        else:
            print_success("DNP3 outstation reachable")
            for hint in (identify.strings or [])[:6]:
                print_info(f"  attr: {hint}")

        additional_data = {
            "host": host,
            "port": port,
            "src": src,
            "dest": dest,
            "protocol": "dnp3",
            "platform": "ics",
            "timeout": timeout,
            "identify_strings": list(identify.strings or []),
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
