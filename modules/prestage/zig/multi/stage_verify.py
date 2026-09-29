#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "stage_verify"

    __info__ = {
        "name": "Stage Verify (Zig)",
        "description": "Verify staged artifact SHA256 before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "staging", "zig"],
    }

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        stage_sha256 = str(ctx.get("prestage_stage_sha256") or "").replace("\\", "\\\\").replace('"', '\\"')
        if not stage_sha256:
            return "// stage_verify: no stage sha256 configured"
        return f"""
    _ = "{stage_sha256}";
    // Use stage_cache prestage for verified staging on Zig payloads.
""".strip()
