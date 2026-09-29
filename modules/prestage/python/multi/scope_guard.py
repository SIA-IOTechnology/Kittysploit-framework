#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List

from kittysploit import *


class Module(Prestage):
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
        from lib.c2.prestage_guards import build_scope_guard_bootstrap

        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").strip()
        raw_scope = str(ctx.get("prestage_scope") or getattr(getattr(self, "allowed_scope", None), "value", "") or "").strip()
        allowed_hosts: List[str] = []
        allowed_cidrs: List[str] = []
        for token in [part.strip() for part in raw_scope.split(",") if part.strip()]:
            if "/" in token:
                allowed_cidrs.append(token)
            else:
                allowed_hosts.append(token)
        if c2_host and c2_host not in allowed_hosts:
            allowed_hosts.append(c2_host)
        return build_scope_guard_bootstrap(
            c2_host=c2_host,
            allowed_hosts=allowed_hosts,
            allowed_cidrs=allowed_cidrs or None,
        )
