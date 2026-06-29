#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extraction gzip / lzma / xz / copie ELF depuis un offset dans un fichier firmware.
"""

from __future__ import annotations

import gzip
import lzma
import os
import zlib
from io import BytesIO
from typing import List, Optional, Tuple

from core.framework.base_module import BaseModule

_GZIP_READ_ERRORS: Tuple[type, ...] = (OSError, EOFError, zlib.error)
if hasattr(gzip, "BadGzipFile"):
    _GZIP_READ_ERRORS = _GZIP_READ_ERRORS + (gzip.BadGzipFile,)


class FirmwareExtract(BaseModule):
    """Helpers gzip / lzma / ELF partagés par les modules firmware."""

    GZIP_MAGIC = b"\x1f\x8b"

    @staticmethod
    def decompress_gzip_bytes(raw: bytes, offset: int = 0) -> bytes:
        """
        Décompresse un flux gzip embarqué dans un buffer (équivalent gunzip sur stdout).

        Essaie ``GzipFile`` puis un repli ``zlib`` (membres piggyback / trailing data).
        """
        chunk = raw[offset:]
        if not chunk:
            raise ValueError("empty gzip input")

        try:
            with gzip.GzipFile(fileobj=BytesIO(chunk), mode="rb") as gz:
                data = gz.read()
            if data:
                return data
        except _GZIP_READ_ERRORS:
            pass

        try:
            data = zlib.decompress(chunk, wbits=16 + zlib.MAX_WBITS)
            if data:
                return data
        except zlib.error as exc:
            raise ValueError("gzip decompression failed") from exc

        raise ValueError("gzip decompression produced empty output")

    @staticmethod
    def load_maybe_gzip_file(path: str) -> Optional[bytes]:
        """Lit un fichier et le décompresse si c'est du gzip, sinon renvoie le contenu brut."""
        try:
            with open(path, "rb") as f:
                raw = f.read()
            if not raw:
                return None
            try:
                return FirmwareExtract.decompress_gzip_bytes(raw)
            except ValueError:
                return raw
        except OSError:
            return None

    @staticmethod
    def extract_gzip(firmware_path: str, output_dir: str, offset: int = 0) -> List[str]:
        """
        Extrait un membre gzip à partir de ``offset`` (chemin fichier, pas buffer).
        """
        os.makedirs(output_dir, exist_ok=True)
        out_path = os.path.join(output_dir, f"extracted_gzip_{offset:x}.bin")

        with open(firmware_path, "rb") as f:
            f.seek(offset)
            raw = f.read()

        if len(raw) < 10 or raw[:2] != FirmwareExtract.GZIP_MAGIC or raw[2] != 8:
            raise ValueError("Not a plausible gzip stream at offset")

        try:
            data = FirmwareExtract.decompress_gzip_bytes(raw)
        except ValueError:
            raise ValueError("Not a plausible gzip stream at offset") from None

        with open(out_path, "wb") as f:
            f.write(data)
        return [out_path]

    @staticmethod
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

    @staticmethod
    def extract_elf(firmware_path: str, output_dir: str, offset: int = 0) -> List[str]:
        """Copie depuis l'offset jusqu'à la fin du fichier (image ELF embarquée)."""
        os.makedirs(output_dir, exist_ok=True)
        out_path = os.path.join(output_dir, f"elf_offset_{offset:x}.bin")
        with open(firmware_path, "rb") as f_in, open(out_path, "wb") as f_out:
            f_in.seek(offset)
            f_out.write(f_in.read())
        return [out_path]


# Alias module-level pour compatibilité interne (handlers, libs tierces)
decompress_gzip_bytes = FirmwareExtract.decompress_gzip_bytes
load_maybe_gzip_file = FirmwareExtract.load_maybe_gzip_file
extract_gzip = FirmwareExtract.extract_gzip
extract_lzma = FirmwareExtract.extract_lzma
extract_elf = FirmwareExtract.extract_elf
