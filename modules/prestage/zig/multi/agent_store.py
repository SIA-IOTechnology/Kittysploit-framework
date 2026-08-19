#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Bootstrap encrypted agent-side task storage before callback (Zig emitter)."""

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.emitters.zig import emit_agent_store


class Module(Prestage):
    PRESTAGE_ID = "agent_store"

    __info__ = {
        "name": "Agent Local Store (Zig)",
        "description": "Bootstrap encrypted local task storage on the implant before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "dependencies": [],
        "tags": ["prestage", "offline", "persistence", "tasks", "zig"],
    }

    store_path = OptString("", "Store file path on target (default: temp/.kitty_store)", False)
    store_secret = OptString("", "Encryption secret (default: kitty-agent-store)", False)

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        return emit_agent_store(self, context)
