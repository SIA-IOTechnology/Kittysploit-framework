"""ELF symbol offset extraction for libphp.so.

Reads the ELF symbol table to find zif_system and zval_ptr_dtor offsets.
These offsets are build-specific: each PHP compilation produces different
symbol addresses. The offsets are relative to the library's load base,
so they work regardless of ASLR.

Can extract from:
  - A running Docker container (copies libphp.so via docker cp)
  - A local libphp.so file
  - The offsets.env file written by a previous extraction
"""
from __future__ import annotations

import os
import struct
import subprocess
import tempfile

SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1

NEEDED_SYMBOLS = {"zif_system", "zval_ptr_dtor"}


def extract_from_elf(path: str) -> tuple[int, int]:
    """Parse an ELF64 binary and return (zif_system_offset, zval_ptr_dtor_offset).

    Offsets are relative to the lowest PT_LOAD virtual address (the load bias),
    matching what the runtime sees after ASLR relocation.
    """
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not a little-endian ELF64 file")

    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)

    # Find the lowest PT_LOAD segment (the load bias)
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", data, off)
        p_vaddr, = struct.unpack_from("<Q", data, off + 16)
        p_memsz, = struct.unpack_from("<Q", data, off + 40)
        if p_type == PT_LOAD and p_memsz:
            loads.append(p_vaddr)
    if not loads:
        raise ValueError("no PT_LOAD segment")
    bias = min(loads)

    # Parse section headers
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from("<II", data, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_link, = struct.unpack_from("<I", data, off + 40)
        sh_entsize, = struct.unpack_from("<Q", data, off + 56)
        sections.append({
            "type": sh_type, "offset": sh_offset, "size": sh_size,
            "link": sh_link, "entsize": sh_entsize,
        })

    # Search symbol tables for our target symbols
    found = {}
    for sec in sections:
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        strtab = sections[sec["link"]] if sec["link"] < len(sections) else None
        if strtab is None:
            continue
        entsize = sec["entsize"] or 24
        count = sec["size"] // entsize
        for i in range(count):
            off = sec["offset"] + i * entsize
            st_name, = struct.unpack_from("<I", data, off)
            st_value, = struct.unpack_from("<Q", data, off + 8)
            if st_name == 0:
                continue
            name_off = strtab["offset"] + st_name
            end = data.find(b"\x00", name_off)
            if end < 0:
                continue
            name = data[name_off:end].decode("ascii", "replace")
            if name in NEEDED_SYMBOLS and name not in found:
                found[name] = st_value - bias

    missing = NEEDED_SYMBOLS - set(found)
    if missing:
        raise ValueError(f"symbols not found in ELF: {', '.join(sorted(missing))}")

    return found["zif_system"], found["zval_ptr_dtor"]


def extract_from_container(container: str,
                           lib_path: str = "/usr/lib/apache2/modules/libphp.so",
                           docker_cmd: str = "docker") -> tuple[int, int]:
    """Copy libphp.so from a Docker container and extract offsets."""
    fd, tmppath = tempfile.mkstemp(prefix="libphp-", suffix=".so")
    os.close(fd)
    try:
        subprocess.run(
            docker_cmd.split() + ["cp", f"{container}:{lib_path}", tmppath],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        return extract_from_elf(tmppath)
    finally:
        os.unlink(tmppath)


def load_offsets_env(path: str) -> tuple[int | None, int | None]:
    """Load offsets from an offsets.env file (ZIF_OFFSET=0x... DTOR_OFFSET=0x...)."""
    zif = None
    dtor = None
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line.startswith("ZIF_OFFSET="):
                zif = int(line.split("=", 1)[1], 16)
            elif line.startswith("DTOR_OFFSET="):
                dtor = int(line.split("=", 1)[1], 16)
    return zif, dtor


def save_offsets_env(path: str, zif: int, dtor: int) -> None:
    """Write offsets to an offsets.env file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"ZIF_OFFSET=0x{zif:x}\n")
        f.write(f"DTOR_OFFSET=0x{dtor:x}\n")
