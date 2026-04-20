#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extraction gzip / lzma / xz / copie ELF depuis un offset dans un fichier.
"""

from __future__ import annotations

import gzip
import lzma
import os
import zlib
from io import BytesIO
from typing import List

_GZIP_READ_ERRORS = (OSError, EOFError, zlib.error)
if hasattr(gzip, "BadGzipFile"):
    _GZIP_READ_ERRORS = _GZIP_READ_ERRORS + (gzip.BadGzipFile,)


def extract_gzip(firmware_path: str, output_dir: str, offset: int = 0) -> List[str]:
    """
    Extrait un membre gzip à partir de ``offset`` (chemin fichier, pas buffer —
    ``gzip.open(bytes)`` est invalide).
    """
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"extracted_gzip_{offset:x}.bin")

    with open(firmware_path, "rb") as f:
        f.seek(offset)
        raw = f.read()

    if len(raw) < 10 or raw[:2] != b"\x1f\x8b" or raw[2] != 8:
        raise ValueError("Not a plausible gzip stream at offset")

    data: bytes
    try:
        with gzip.GzipFile(fileobj=BytesIO(raw), mode="rb") as gz:
            data = gz.read()
    except _GZIP_READ_ERRORS:
        data = zlib.decompress(raw, wbits=16 + zlib.MAX_WBITS)

    if not data:
        raise ValueError("Gzip extraction produced empty output")

    with open(out_path, "wb") as f:
        f.write(data)
    return [out_path]


def extract_lzma(firmware_path: str, output_dir: str, offset: int = 0) -> List[str]:
    """Extrait xz ou lzma alone à partir de ``offset``."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"extracted_lzma_{offset:x}.bin")

    with open(firmware_path, "rb") as f:
        f.seek(offset)
        raw = f.read()

    bio = BytesIO(raw)
    try:
        with lzma.open(bio) as lz:
            data = lz.read()
    except (lzma.LZMAError, EOFError):
        bio.seek(0)
        with lzma.open(bio, format=lzma.FORMAT_ALONE) as lz:
            data = lz.read()

    with open(out_path, "wb") as f:
        f.write(data)
    return [out_path]


def extract_elf(firmware_path: str, output_dir: str, offset: int = 0) -> List[str]:
    """Copie depuis l’offset jusqu’à la fin du fichier (image ELF embarquée)."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"elf_offset_{offset:x}.bin")
    with open(firmware_path, "rb") as f_in, open(out_path, "wb") as f_out:
        f_in.seek(offset)
        f_out.write(f_in.read())
    return [out_path]
