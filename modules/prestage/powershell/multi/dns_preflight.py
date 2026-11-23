#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards import Prestage_guards


class Module(Prestage, Prestage_guards):
    PRESTAGE_ID = "dns_preflight"

    __info__ = {
        "name": "DNS Preflight (PowerShell)",
        "description": "Resolve callback hostname before TCP preflight or main implant loop",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "network", "dns", "powershell"],
    }

    timeout = OptString("3", "DNS lookup timeout in seconds", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").strip()
        try:
            timeout_ms = int(float(getattr(getattr(self, "timeout", None), "value", self.timeout) or 3) * 1000)
        except (TypeError, ValueError):
            timeout_ms = 3000
        return self.build_dns_preflight_powershell(c2_host=c2_host, timeout_ms=timeout_ms)