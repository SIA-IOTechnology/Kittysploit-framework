#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from lib.c2.prestage_guards import Prestage_guards


class Module(Prestage, Prestage_guards):
    PRESTAGE_ID = "stage_verify"

    __info__ = {
        "name": "Stage Verify (PowerShell)",
        "description": "Verify staged artifact SHA256 before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "staging", "powershell"],
    }

    stage_url = OptString("", "Stage URL to verify", False)
    stage_sha256 = OptString("", "Expected SHA256 of staged artifact", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        stage_url = str(
            ctx.get("prestage_stage_url")
            or getattr(getattr(self, "stage_url", None), "value", "")
            or ""
        ).strip()
        stage_sha256 = str(
            ctx.get("prestage_stage_sha256")
            or getattr(getattr(self, "stage_sha256", None), "value", "")
            or ""
        ).strip()
        return self.build_stage_verify_powershell(stage_url=stage_url, stage_sha256=stage_sha256)