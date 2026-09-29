#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "network_preflight"

    __info__ = {
        "name": "Network Preflight (Python)",
        "description": "Probe callback reachability before entering the main implant loop",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "network", "python"],
    }

    timeout = OptString("3", "TCP connect timeout in seconds", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        from lib.c2.prestage_guards import build_network_preflight_bootstrap

        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").strip()
        c2_port = int(ctx.get("c2_port") or 8088)
        try:
            timeout = float(getattr(getattr(self, "timeout", None), "value", self.timeout) or 3)
        except (TypeError, ValueError):
            timeout = 3.0
        if not c2_host:
            return "pass  # network_preflight: set lhost on payload"
        return build_network_preflight_bootstrap(c2_host=c2_host, c2_port=c2_port, timeout=timeout)
