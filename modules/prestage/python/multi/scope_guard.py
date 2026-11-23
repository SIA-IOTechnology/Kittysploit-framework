#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards import Prestage_guards


class Module(Prestage, Prestage_guards):
    PRESTAGE_ID = "scope_guard"

    __info__ = {
        "name": "Scope Guard (Python)",
        "description": "Exit when the callback host is outside the embedded lab scope",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "guard", "python"],
    }

    allowed_scope = OptString(
        "",
        "Extra allowed hosts/CIDRs (comma-separated, merged with private ranges)",
        False,
    )

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").strip()
        raw_scope = str(
            ctx.get("prestage_scope") or getattr(getattr(self, "allowed_scope", None), "value", "") or ""
        ).strip()
        allowed_hosts, allowed_cidrs = self.parse_scope_selection(raw_scope, c2_host=c2_host)
        return self.build_scope_guard_bootstrap(
            c2_host=c2_host,
            allowed_hosts=allowed_hosts,
            allowed_cidrs=allowed_cidrs or None,
        )