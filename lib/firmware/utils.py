#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Détection de formats dans un buffer (en-têtes fixes + scan gzip / lzma / squashfs).
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from lib.analysis.binary.firmware_extractor import PyFirmwareExtractor


def _looks_gzip(data: bytes, off: int) -> bool:
    return PyFirmwareExtractor._looks_like_gzip_header(data, off)


def detect_firmware_type(
    data: bytes,
    supported_formats: Dict[str, Dict[str, Any]],
) -> List[Tuple[str, int]]:
    """
    Retourne ``(format_id, offset)`` triés par offset. Les entrées avec
    ``"scan": True`` cherchent la première occurrence plausible dans ``data``.
    """
    found: List[Tuple[str, int]] = []
    seen: set = set()

    def add(fmt: str, pos: int) -> None:
        key = (fmt, pos)
        if key not in seen:
            seen.add(key)
            found.append((fmt, pos))

    for fmt in sorted(supported_formats.keys()):
        cfg = supported_formats[fmt]
        magic: bytes = cfg["magic"]
        off = int(cfg.get("offset", 0))
        scan = bool(cfg.get("scan", False))

        if fmt == "gzip":
            start = 0
            while True:
                pos = data.find(b"\x1f\x8b", start)
                if pos < 0:
                    break
                if _looks_gzip(data, pos):
                    add("gzip", pos)
                    break
                start = pos + 1
            continue

        if fmt == "lzma" and scan:
            pos_xz = data.find(b"\xfd\x37\x7a\x58\x5a\x00")
            pos_alone = data.find(b"!\x18")
            candidates = [p for p in (pos_xz, pos_alone) if p >= 0]
            if candidates:
                add("lzma", min(candidates))
            continue

        if fmt == "squashfs" and scan:
            for sig in (b"hsqs", b"sqsh", b"\x37\x7a\xbc\xaf\x27\x1c"):
                pos = data.find(sig)
                if pos >= 0:
                    add("squashfs", pos)
                    break
            continue

        if off + len(magic) > len(data):
            continue
        if data[off : off + len(magic)] != magic:
            continue
        add(fmt, off)

    found.sort(key=lambda x: x[1])
    return found


def filter_gzip_redundant_with_trx(
    detected: List[Tuple[str, int]],
) -> List[Tuple[str, int]]:
    """
    Si un TRX est présent à l’offset classique 0x20, retire le gzip à l’offset
    payload TRX (0x20 + 28) pour éviter une double extraction.
    """
    trx_off = next((o for f, o in detected if f == "trx"), None)
    if trx_off is None:
        return detected
    payload = trx_off + 28
    return [(f, o) for f, o in detected if not (f == "gzip" and o == payload)]


SUPPORTED_FORMATS_DEFAULT: Dict[str, Dict[str, Any]] = {
    "trx": {"magic": b"HDR0", "offset": 0x20, "scan": False},
    "gzip": {"magic": b"\x1f\x8b", "offset": 0, "scan": True},
    "lzma": {"magic": b"!\x18", "offset": 0, "scan": True},
    "elf": {"magic": b"\x7fELF", "offset": 0, "scan": False},
    "squashfs": {"magic": b"hsqs", "offset": 0, "scan": True},
}
