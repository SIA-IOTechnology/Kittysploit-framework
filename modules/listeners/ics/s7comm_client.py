#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""S7comm bind listener — opens an ISO-on-TCP session to a Siemens PLC."""

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.s7_client import S7Client, snap7_available


class Module(Listener):
    __info__ = {
        "name": "S7comm Client",
        "description": "Connects to a Siemens S7 PLC and creates an interactive S7comm shell session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.S7COMM,
        "protocol": "s7comm",
    }

    rhost = OptString("127.0.0.1", "Target PLC IP or hostname", True)
    rport = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "S7comm port", True)
    rack = OptInteger(0, "PLC rack number", False)
    slot = OptInteger(1, "PLC slot number", False)
    password = OptString("", "Optional S7 session password", False)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport)
        rack = int(self.rack or 0)
        slot = int(self.slot or 1)
        password = str(self.password or "")

        backend = "snap7" if snap7_available() else "raw ISO-on-TCP"
        print_status(f"Connecting to S7comm {host}:{port} (rack={rack}, slot={slot}, backend={backend})...")

        client = S7Client(
            host,
            port,
            float(self.timeout or 5),
            rack,
            slot,
            password,
        )
        if not client.connect():
            print_error(f"S7comm connection failed for {host}:{port}")
            return False

        identity = client.identify()
        print_success(f"S7comm session established with {host}:{port}")
        print_info(f"  Module: {identity.module_type_name or 'unknown'}")
        print_info(f"  Protection: {identity.protection_label}")

        additional_data = {
            "host": host,
            "port": port,
            "rack": rack,
            "slot": slot,
            "password": password,
            "protocol": "s7comm",
            "platform": "ics",
            "backend": identity.backend,
            "module_type_name": identity.module_type_name,
            "serial_number": identity.serial_number,
            "firmware": identity.firmware,
            "protection_level": identity.protection_level,
            "protection_label": identity.protection_label,
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
