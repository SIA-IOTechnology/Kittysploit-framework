#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Build a minimal x64 DLL PE wrapping raw shellcode with an exported entry point."""

from __future__ import annotations

import struct


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_shellcode_dll(shellcode: bytes, export_name: str = "Execute", dll_name: str = "payload.dll") -> bytes:
    """Return a valid AMD64 DLL with shellcode in .text and one named export."""
    if not shellcode:
        raise ValueError("shellcode is empty")
    if len(shellcode) > 0xF000:
        raise ValueError("shellcode too large for minimal DLL builder")

    file_align = 0x200
    sect_align = 0x1000

    dll_main = b"\xB8\x01\x00\x00\x00\xC3"
    execute_rva = len(dll_main)
    text_content = dll_main + shellcode
    text_content = text_content.ljust(_align(len(text_content), 16), b"\x00")
    text_virtual_size = _align(len(text_content), sect_align)

    export_name_b = export_name.encode("ascii") + b"\x00"
    dll_name_b = dll_name.encode("ascii") + b"\x00"
    num_exports = 1

    export_dir = bytearray(40)
    struct.pack_into(
        "<IIHHIIIIII",
        export_dir,
        0,
        0,
        0,
        0xFFFF,
        0xFFFF,
        0,
        1,
        num_exports,
        num_exports,
        0,
        0,
    )

    edata_content = bytearray()
    edata_content += export_dir
    edata_content += b"\x00" * (4 * num_exports)
    edata_content += b"\x00" * (4 * num_exports)
    edata_content += b"\x00" * (2 * num_exports)
    edata_content += dll_name_b + export_name_b
    edata_content = edata_content.ljust(_align(len(edata_content), 16), b"\x00")
    edata_virtual_size = _align(len(edata_content), sect_align)

    text_rva = sect_align
    edata_rva = text_rva + text_virtual_size
    size_of_image = _align(edata_rva + edata_virtual_size, sect_align)

    name_dll_rva = edata_rva + 40 + 4 * num_exports + 4 * num_exports + 2 * num_exports
    name_export_rva = name_dll_rva + len(dll_name_b)

    struct.pack_into("<I", edata_content, 12, name_dll_rva)
    struct.pack_into("<I", edata_content, 28, edata_rva + 40)
    struct.pack_into("<I", edata_content, 32, edata_rva + 40 + 4 * num_exports)
    struct.pack_into("<I", edata_content, 36, edata_rva + 40 + 8 * num_exports)
    struct.pack_into("<I", edata_content, 40, text_rva + execute_rva)
    struct.pack_into("<I", edata_content, 44, name_export_rva)
    struct.pack_into("<H", edata_content, 48, 0)

    headers_size = 0x180
    text_raw_ptr = _align(headers_size, file_align)
    edata_raw_ptr = text_raw_ptr + _align(len(text_content), file_align)

    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$"
    pe_offset = _align(64 + len(dos_stub), 16)
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)

    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x2022)

    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    opt[2] = 0x0E
    struct.pack_into("<I", opt, 4, len(text_content))
    struct.pack_into("<I", opt, 8, len(edata_content))
    struct.pack_into("<I", opt, 16, text_rva)
    struct.pack_into("<Q", opt, 24, 0x180000000)
    struct.pack_into("<I", opt, 32, sect_align)
    struct.pack_into("<I", opt, 36, file_align)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<H", opt, 70, 0x8160)
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, headers_size)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112, edata_rva, edata_virtual_size)

    text_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        text_virtual_size,
        text_rva,
        len(text_content),
        text_raw_ptr,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    edata_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".edata\x00\x00",
        edata_virtual_size,
        edata_rva,
        len(edata_content),
        edata_raw_ptr,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    pe = b"PE\x00\x00" + coff + bytes(opt) + text_hdr + edata_hdr
    header = bytes(dos) + dos_stub + b"\x00" * (pe_offset - 64 - len(dos_stub))
    image = header + pe
    image = image.ljust(text_raw_ptr, b"\x00")
    image += bytes(text_content).ljust(_align(len(text_content), file_align), b"\x00")
    image += bytes(edata_content).ljust(_align(len(edata_content), file_align), b"\x00")
    return image
