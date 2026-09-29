#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "resource_guard"

    __info__ = {
        "name": "Resource Guard (Python)",
        "description": "Exit early when memory or disk looks too constrained for the intended target",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "guard", "python"],
    }

    min_mem_mb = OptString("32", "Minimum physical memory in MB", False)
    min_disk_mb = OptString("10", "Minimum free disk in MB", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        from lib.c2.prestage_guards import build_resource_guard_bootstrap

        try:
            min_mem = int(getattr(getattr(self, "min_mem_mb", None), "value", self.min_mem_mb) or 32)
        except (TypeError, ValueError):
            min_mem = 32
        try:
            min_disk = int(getattr(getattr(self, "min_disk_mb", None), "value", self.min_disk_mb) or 10)
        except (TypeError, ValueError):
            min_disk = 10
        return build_resource_guard_bootstrap(min_mem_mb=min_mem, min_disk_mb=min_disk)
