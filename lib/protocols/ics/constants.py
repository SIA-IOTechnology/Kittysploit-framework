#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Well-known ICS/SCADA TCP ports and default passive capture filter."""

from __future__ import annotations

ICS_TCP_PORTS: dict[int, str] = {
    502: "modbus-tcp",
    102: "s7comm",
    44818: "enip",
    20000: "dnp3",
    2404: "iec104",
    4840: "opcua",
}

ICS_UDP_PORTS: dict[int, str] = {
    47808: "bacnet",
}

ICS_PROTOCOL_PORTS: dict[str, int] = {
    "modbus-tcp": 502,
    "s7comm": 102,
    "enip": 44818,
    "dnp3": 20000,
    "iec104": 2404,
    "bacnet": 47808,
    "opcua": 4840,
}

DEFAULT_ICS_BPF = " or ".join(
    [*(f"tcp port {port}" for port in sorted(ICS_TCP_PORTS)),
     *(f"udp port {port}" for port in sorted(ICS_UDP_PORTS))]
)

# Common OT vendor OUI prefixes (subset — full DB in data/vendors/oui.json).
OT_OUI_HINTS: dict[str, str] = {
    "000E8C": "Siemens",
    "001B1E": "Siemens",
    "000BC5": "Rockwell Automation",
    "0001C0": "Rockwell Automation",
    "001D9C": "Schneider Electric",
    "0009FB": "Schneider Electric",
    "001B1B": "ABB",
    "000BC6": "Moxa",
    "0060E7": "Moxa",
    "000822": "Phoenix Contact",
    "001E67": "Beckhoff",
}

MODBUS_WRITE_FUNCTION_CODES = frozenset({5, 6, 15, 16, 22, 23})

S7_DANGEROUS_JOBS = frozenset({0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F})
