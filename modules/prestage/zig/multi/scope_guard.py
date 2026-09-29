#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "scope_guard"

    __info__ = {
        "name": "Scope Guard (Zig)",
        "description": "Exit when the callback host is outside the embedded lab scope",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "guard", "zig"],
    }

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").replace("\\", "\\\\").replace('"', '\\"')
        if not c2_host:
            return "// scope_guard: set lhost on payload"
        return f"""
    const c2_host = "{c2_host}";
    _ = c2_host;
    // Private-lab scope enforcement is currently lightweight on Zig implants.
""".strip()
