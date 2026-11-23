#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards import Prestage_guards


class Module(Prestage, Prestage_guards):
    PRESTAGE_ID = "network_preflight"

    __info__ = {
        "name": "Network Preflight (PowerShell)",
        "description": "Probe callback reachability before entering the main implant loop",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "network", "powershell"],
    }

    timeout = OptString("3", "TCP connect timeout in seconds", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").strip()
        c2_port = int(ctx.get("c2_port") or 8088)
        if not c2_host:
            return "# network_preflight: set lhost on payload"
        try:
            timeout_ms = int(float(getattr(getattr(self, "timeout", None), "value", self.timeout) or 3) * 1000)
        except (TypeError, ValueError):
            timeout_ms = 3000
        return self.build_network_preflight_powershell(
            c2_host=c2_host,
            c2_port=c2_port,
            timeout_ms=timeout_ms,
        )