#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Extract an embedded ZIP archive before callback (PowerShell emitter)."""

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.emitters.powershell import emit_extract_zip


class Module(Prestage):
    PRESTAGE_ID = "extract_zip"

    __info__ = {
        "name": "Extract Embedded ZIP (PowerShell)",
        "description": "Extract a ZIP archive embedded at generation time before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "dependencies": [],
        "tags": ["prestage", "offline", "zip", "staging", "powershell"],
    }

    zip_file = OptFile("", "ZIP archive on operator machine (embedded during generate)", False)
    extract_to = OptString("", "Destination directory on target (default: temp dir)", False)
    cleanup_zip = OptBool(True, "Remove extracted tree on failure after partial extract", False, True)
    chmod_exec = OptBool(True, "Mark extracted files executable (Unix pwsh)", False, True)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        return emit_extract_zip(self, context)
