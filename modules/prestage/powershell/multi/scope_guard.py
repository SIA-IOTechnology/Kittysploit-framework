#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards import Prestage_guards


class Module(Prestage, Prestage_guards):
    PRESTAGE_ID = "scope_guard"

    __info__ = {
        "name": "Scope Guard (PowerShell)",
        "description": "Exit when the callback host is outside the embedded lab scope",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "guard", "powershell"],
    }

    allowed_scope = OptString("", "Extra allowed hosts/CIDRs (comma-separated)", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").strip()
        raw_scope = str(
            ctx.get("prestage_scope") or getattr(getattr(self, "allowed_scope", None), "value", "") or ""
        ).strip()
        return self.build_scope_guard_powershell(c2_host=c2_host, extra_scope_csv=raw_scope)