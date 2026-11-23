#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards import Prestage_guards


class Module(Prestage, Prestage_guards):
    PRESTAGE_ID = "dns_preflight"

    __info__ = {
        "name": "DNS Preflight (Python)",
        "description": "Resolve callback hostname before TCP preflight or main implant loop",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "network", "dns", "python"],
    }

    timeout = OptString("3", "DNS lookup timeout in seconds", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").strip()
        try:
            timeout = float(getattr(getattr(self, "timeout", None), "value", self.timeout) or 3)
        except (TypeError, ValueError):
            timeout = 3.0
        return self.build_dns_preflight_bootstrap(c2_host=c2_host, timeout=timeout)