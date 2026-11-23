#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards import Prestage_guards


class Module(Prestage, Prestage_guards):
    PRESTAGE_ID = "single_instance"

    __info__ = {
        "name": "Single Instance (PowerShell)",
        "description": "Exit when another copy of this implant is already running on the host",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "guard", "powershell"],
    }

    lock_id = OptString(
        "",
        "Lock name suffix (default: derived from c2 host or kitty_implant)",
        False,
    )

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        lock_id = self.resolve_lock_id(
            ctx,
            module_lock=str(getattr(getattr(self, "lock_id", None), "value", "") or ""),
        )
        return self.build_single_instance_powershell(lock_id=lock_id)