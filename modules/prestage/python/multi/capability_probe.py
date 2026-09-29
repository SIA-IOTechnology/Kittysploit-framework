#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "capability_probe"

    __info__ = {
        "name": "Capability Probe (Python)",
        "description": (
            "Detect OS, architecture, runtime, privileges, writable directory, "
            "and network capabilities before callback"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "dependencies": [],
        "tags": ["recon", "prestage", "offline", "python"],
    }

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        from lib.c2.capability_probe import build_capability_probe_bootstrap

        return build_capability_probe_bootstrap()
