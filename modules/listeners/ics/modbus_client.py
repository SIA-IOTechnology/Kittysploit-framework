#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Modbus TCP bind listener — opens a Modbus session for interactive register access."""

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.modbus_client import ModbusTCPClient


class Module(Listener):
    __info__ = {
        "name": "Modbus TCP Client",
        "description": "Connects to a Modbus TCP server and creates an interactive Modbus shell session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.MODBUS,
        "protocol": "modbus-tcp",
    }

    rhost = OptString("127.0.0.1", "Target Modbus host", True)
    rport = OptPort(ICS_PROTOCOL_PORTS["modbus-tcp"], "Modbus TCP port", True)
    unit_id = OptInteger(1, "Default Modbus unit ID", False)
    unit_start = OptInteger(1, "First unit ID to scan on connect", False, advanced=True)
    unit_end = OptInteger(32, "Last unit ID to scan on connect", False, advanced=True)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport)
        unit_id = int(self.unit_id or 1)
        timeout = float(self.timeout or 5)

        print_status(f"Connecting to Modbus TCP {host}:{port}...")
        client = ModbusTCPClient(host, port, timeout)
        if not client.connect():
            print_error(f"Modbus TCP connection failed for {host}:{port}")
            return False

        units = [
            {"unit_id": item.unit_id, "registers": item.values[:8], "function_code": item.function_code}
            for item in client.scan_unit_ids(int(self.unit_start or 1), int(self.unit_end or 32))
        ]
        if units:
            print_success(f"Modbus TCP reachable — {len(units)} responsive unit ID(s)")
            for item in units[:8]:
                print_info(f"  unit_id={item.get('unit_id')}")
        else:
            print_warning("Modbus TCP connected but no responsive unit IDs found in scan range")

        additional_data = {
            "host": host,
            "port": port,
            "unit_id": unit_id,
            "units": units,
            "protocol": "modbus-tcp",
            "platform": "ics",
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
