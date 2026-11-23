#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-116442 — PowerStore NDMP server info leak."""

from kittysploit import *
from lib.protocols.tcp.ndmp_client import Ndmp
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Auxiliary, Tcp_scanner_client, Ndmp):
    __info__ = {
        "name": "PowerStore NDMP CVE-2026-116442 probe",
        "description": "Displays NDMP CONFIG_GET_SERVER_INFO fields.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-116442"],
        "tags": ["dell", "powerstore", "ndmp", "auxiliary"],
        "agent": {"approval_required": False, "produces": ["risk_signals"]},
    }

    port = OptPort(10000, "NDMP port", required=False)

    def run(self):
        status, info, raw = self.ndmp_probe()
        print_status(f"NDMP status: {status}")
        for key, val in info.items():
            print_status(f"  {key}: {val}")
        if not info and raw:
            print_status(f"raw: {raw[:64].hex()}...")
        return status in ("vulnerable", "responded")