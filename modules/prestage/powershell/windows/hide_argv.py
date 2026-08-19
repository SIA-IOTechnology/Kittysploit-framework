#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "hide_argv"

    __info__ = {
        "name": "Hide Process Title (PowerShell)",
        "description": "Set console title to a benign value before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.WINDOWS,
        "languages": ["powershell"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "powershell"],
    }

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        title = "Windows PowerShell"
        if context and context.get("process_title"):
            title = str(context["process_title"])
        return f"""
$host.UI.RawUI.WindowTitle = '{title.replace("'", "''")}'
""".strip()
