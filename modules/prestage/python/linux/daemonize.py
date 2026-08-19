#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "daemonize"

    __info__ = {
        "name": "Daemonize Process (Python)",
        "description": "Detach from the controlling terminal on Unix (double-fork)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.UNIX,
        "languages": ["python"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "linux", "python"],
    }

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        return """
import os
import sys
if hasattr(os, "fork"):
    try:
        if os.fork() > 0:
            sys.exit(0)
        os.setsid()
        if os.fork() > 0:
            sys.exit(0)
        try:
            os.chdir("/")
        except Exception:
            pass
        with open(os.devnull, "r") as _dn:
            os.dup2(_dn.fileno(), 0)
        with open(os.devnull, "w") as _dn:
            os.dup2(_dn.fileno(), 1)
            os.dup2(_dn.fileno(), 2)
    except Exception:
        pass
""".strip()
