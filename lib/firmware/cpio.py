#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lecture et extraction d'archives CPIO newc (SVR4, magic 070701).
"""

from __future__ import annotations

import os
import stat
from typing import Dict, Iterable, Iterator, List, Optional

from lib.firmware.extract import FirmwareExtract


class CpioArchive:
    """Extracteur CPIO newc en pur Python."""

    NEWC_MAGIC = b"070701"
    TRAILER_NAME = "TRAILER!!!"
    HEADER_SIZE = 110

    @classmethod
    def _read_hex_field(cls, header: bytes, start: int) -> int:
        return int(header[start : start + 8], 16)

    @staticmethod
    def _pad4(n: int) -> int:
        return (4 - (n % 4)) % 4

    @classmethod
    def _align4(cls, n: int) -> int:
        return n + cls._pad4(n)

    @staticmethod
    def _safe_relative_name(name: str, strip: int = 0) -> Optional[str]:
        rel = name.replace("\\", "/").lstrip("/")
        if rel.startswith("./"):
            rel = rel[2:]

        parts = [part for part in rel.split("/") if part not in ("", ".")]
        if strip:
            parts = parts[strip:]
        if not parts or any(part == ".." for part in parts):
            return None
        return os.path.join(*parts)

    @classmethod
    def iter_entries(cls, data: bytes) -> Iterator[dict]:
        """Parcourt les entrées d'une archive newc."""
        offset = 0
        total = len(data)

        while offset + cls.HEADER_SIZE <= total:
            magic = data[offset : offset + 6]
            if magic != cls.NEWC_MAGIC:
                raise ValueError(f"invalid CPIO magic at offset 0x{offset:x}: {magic!r}")

            header = data[offset : offset + cls.HEADER_SIZE]
            namesize = cls._read_hex_field(header, 94)
            filesize = cls._read_hex_field(header, 54)
            mode = cls._read_hex_field(header, 14)

            name_offset = offset + cls.HEADER_SIZE
            name_end = name_offset + namesize - 1
            if name_end > total:
                raise ValueError("truncated CPIO filename")

            name = data[name_offset:name_end].decode("utf-8", errors="replace")
            data_offset = cls._align4(name_offset + namesize)

            if data_offset + filesize > total:
                raise ValueError(f"truncated CPIO payload for {name!r}")

            payload = data[data_offset : data_offset + filesize]
            next_offset = cls._align4(data_offset + filesize)

            yield {
                "name": name,
                "mode": mode,
                "filesize": filesize,
                "data": payload,
                "is_dir": stat.S_ISDIR(mode),
                "is_symlink": stat.S_ISLNK(mode),
                "is_reg": stat.S_ISREG(mode),
            }

            offset = next_offset
            if name == cls.TRAILER_NAME:
                break

    @classmethod
    def extract(
        cls,
        cpio_data: bytes,
        output_dir: str,
        *,
        strip: int = 0,
    ) -> int:
        """
        Extrait une archive newc vers ``output_dir``.

        Retourne le nombre d'entrées écrites (fichiers + répertoires).
        """
        os.makedirs(output_dir, exist_ok=True)
        written = 0

        for entry in cls.iter_entries(cpio_data):
            name = entry["name"]
            if name == cls.TRAILER_NAME:
                break

            rel = cls._safe_relative_name(name, strip)
            if not rel:
                continue

            dest = os.path.join(output_dir, rel)
            real_output_dir = os.path.realpath(output_dir)
            real_parent = os.path.realpath(os.path.dirname(dest) or output_dir)
            if os.path.commonpath([real_output_dir, real_parent]) != real_output_dir:
                continue

            if entry["is_dir"]:
                os.makedirs(dest, exist_ok=True)
                written += 1
                continue

            if entry["is_symlink"]:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                target = entry["data"].decode("utf-8", errors="replace").rstrip("\x00")
                if os.path.lexists(dest):
                    os.remove(dest)
                os.symlink(target, dest)
                written += 1
                continue

            if entry["is_reg"] or entry["filesize"] > 0:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(entry["data"])
                try:
                    os.chmod(dest, entry["mode"] & 0o7777)
                except OSError:
                    pass
                written += 1

        return written

    @classmethod
    def extract_from_gzip(cls, gzip_data: bytes, output_dir: str, *, strip: int = 0) -> int:
        """Décompresse un membre gzip puis extrait le CPIO qu'il contient."""
        cpio_data = FirmwareExtract.decompress_gzip_bytes(gzip_data)
        return cls.extract(cpio_data, output_dir, strip=strip)

    @classmethod
    def list_entries(cls, data: bytes) -> List[dict]:
        """Liste les métadonnées des entrées sans extraire sur disque."""
        return [
            {k: v for k, v in entry.items() if k != "data"}
            for entry in cls.iter_entries(data)
            if entry["name"] != cls.TRAILER_NAME
        ]
