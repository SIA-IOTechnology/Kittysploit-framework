#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.telemetry_context import resolve_telemetry_context


class Module(Prestage):
    PRESTAGE_ID = "telemetry_buffer"

    __info__ = {
        "name": "Telemetry Buffer (Python)",
        "description": "Persist bootstrap errors locally and flush them after the first C2 poll",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "dependencies": [],
        "tags": ["prestage", "offline", "telemetry", "python"],
    }

    buffer_path = OptString("", "Telemetry JSON path on target (default: temp/.kitty_telemetry.json)", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        from lib.c2.telemetry_buffer import build_telemetry_buffer_bootstrap

        cfg = resolve_telemetry_context(self, context)
        buffer_path = cfg["buffer_path"]
        if buffer_path:
            return build_telemetry_buffer_bootstrap(buffer_path)
        return (
            "import tempfile as _tmp\n"
            + build_telemetry_buffer_bootstrap(
                "_tmp.gettempdir() + '/.kitty_telemetry.json'",
                path_is_expression=True,
            )
        )
