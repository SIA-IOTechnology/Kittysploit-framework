#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "stage_verify"

    __info__ = {
        "name": "Stage Verify (Python)",
        "description": "Verify staged artifact SHA256 before callback (uses stage_cache when present)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "staging", "python"],
    }

    stage_url = OptString("", "Stage URL to verify", False)
    stage_sha256 = OptString("", "Expected SHA256 of staged artifact", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        from lib.c2.prestage_guards import build_stage_verify_bootstrap

        ctx = dict(context or {})
        stage_url = str(
            ctx.get("prestage_stage_url")
            or ctx.get("stage_url")
            or getattr(getattr(self, "stage_url", None), "value", "")
            or ""
        ).strip()
        stage_sha256 = str(
            ctx.get("prestage_stage_sha256")
            or getattr(getattr(self, "stage_sha256", None), "value", "")
            or ""
        ).strip()
        return build_stage_verify_bootstrap(stage_url=stage_url, stage_sha256=stage_sha256)
