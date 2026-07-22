#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""DoIP bind listener — connects to a DoIP gateway and opens a diagnostic session."""

from kittysploit import *
from lib.protocols.doip.constants import (
    DOIP_ACTIVATION_DEFAULT,
    DOIP_DEFAULT_PORT,
    DOIP_TESTER_ADDRESS_DEFAULT,
)
from lib.protocols.doip.doip_client import DoIPClient


def _parse_addr(value, default=0):
    try:
        return int(str(value if value is not None else default).strip() or default, 0) & 0xFFFF
    except ValueError:
        return None


class Module(Listener):
    __info__ = {
        "name": "DoIP Client",
        "description": (
            "Connects to an automotive DoIP (ISO 13400) gateway, performs routing "
            "activation, and creates a session for UDS diagnostic post modules"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.DOIP,
        "protocol": "doip",
        "references": [
            "https://en.wikipedia.org/wiki/Diagnostics_over_IP",
            "ISO 13400-2",
            "ISO 14229-1 (UDS)",
        ],
    }

    rhost = OptString("127.0.0.1", "Target DoIP gateway / ECU host", True)
    rport = OptPort(DOIP_DEFAULT_PORT, "DoIP TCP port", True)
    source_address = OptString("0x0E00", "Tester logical address (hex)", True)
    target_address = OptString(
        "0x0000",
        "ECU logical address (0x0000 = use entity address from routing activation)",
        False,
    )
    activation_type = OptString("0x00", "Routing activation type (0x00=default)", False)
    auto_activate = OptBool(True, "Perform routing activation on connect", True)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport)
        source = _parse_addr(self.source_address, DOIP_TESTER_ADDRESS_DEFAULT)
        target = _parse_addr(self.target_address, 0)
        activation = _parse_addr(self.activation_type, DOIP_ACTIVATION_DEFAULT)
        if source is None or target is None or activation is None:
            print_error("Invalid source_address, target_address, or activation_type")
            return False
        activation &= 0xFF
        timeout = float(self.timeout or 5)
        activate = bool(self.auto_activate)

        print_status(
            f"Connecting to DoIP {host}:{port} "
            f"(tester=0x{source:04X}, target=0x{target:04X})..."
        )
        client = DoIPClient(
            host,
            port,
            timeout,
            source,
            target,
            activation,
        )
        if not client.connect(activate=activate):
            print_error(f"DoIP connection/routing activation failed for {host}:{port}")
            return False

        entity = client.entity_address
        print_success(f"DoIP session established with {host}:{port}")
        print_info(f"  Tester address : 0x{client.source_address:04X}")
        if entity is not None:
            print_info(f"  Entity address : 0x{entity:04X}")
        print_info(f"  Target address : 0x{client.target_address:04X}")
        print_info(f"  Routing active : {client.routing_active}")

        additional_data = {
            "host": host,
            "port": port,
            "source_address": client.source_address,
            "target_address": client.target_address,
            "entity_address": entity,
            "activation_type": activation,
            "routing_active": client.routing_active,
            "timeout": timeout,
            "protocol": "doip",
            "platform": "automotive",
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
