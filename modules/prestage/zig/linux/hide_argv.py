#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.emitters.zig import emit_hide_argv


class Module(Prestage):
    PRESTAGE_ID = "hide_argv"

    __info__ = {
        "name": "Hide Process argv (Zig)",
        "description": "Replace process name with an innocuous value on Linux",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.UNIX,
        "languages": ["zig"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "linux", "zig"],
    }

    fake_name = OptString("/usr/sbin/sshd", "Process name shown in ps/top", False)

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        return emit_hide_argv(self, context)
