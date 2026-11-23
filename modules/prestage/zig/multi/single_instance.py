#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards_zig import Prestage_guards_zig


class Module(Prestage, Prestage_guards_zig):
    PRESTAGE_ID = "single_instance"

    __info__ = {
        "name": "Single Instance (Zig)",
        "description": "Exit when another copy of this implant is already running on the host",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "guard", "zig"],
    }

    lock_id = OptString(
        "",
        "Lock name suffix (default: derived from c2 host or kitty_implant)",
        False,
    )

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        lock_id = self.resolve_lock_id(
            ctx,
            module_lock=str(getattr(getattr(self, "lock_id", None), "value", "") or ""),
        )
        return self.build_single_instance_zig(lock_id=lock_id)