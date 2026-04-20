#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TRX (Broadcom / routeurs) : en-tête ``HDR0``, charge utile souvent en gzip à offset+28.
"""

from __future__ import annotations

import os
from typing import List

from lib.firmware.extract import extract_gzip

# En-tête TRX minimal : magic 4 + len 4 + crc 4 + flags 4 + 3 offsets 12 = 28 octets après le début du bloc TRX
_TRX_HEADER_LEN = 28


def extract_trx(firmware_path: str, output_dir: str, offset: int = 0x20) -> List[str]:
    """
    Vérifie ``HDR0`` à ``offset``, puis tente d’extraire la première couche gzip
    typiquement à ``offset + 28`` (structure TRX courante).
    """
    os.makedirs(output_dir, exist_ok=True)

    with open(firmware_path, "rb") as f:
        f.seek(offset)
        header = f.read(_TRX_HEADER_LEN + 4)

    if len(header) < 4 or header[:4] != b"HDR0":
        raise ValueError("Not a TRX firmware (missing HDR0 at given offset)")

    payload_off = offset + _TRX_HEADER_LEN
    with open(firmware_path, "rb") as f:
        f.seek(payload_off)
        peek = f.read(3)

    out: List[str] = []
    if len(peek) >= 2 and peek[:2] == b"\x1f\x8b":
        out.extend(extract_gzip(firmware_path, output_dir, payload_off))
        return out

    # Pas de gzip au slot attendu : copie brute de la zone après en-tête pour inspection
    raw_path = os.path.join(output_dir, f"trx_payload_after_hdr_{offset:x}.bin")
    with open(firmware_path, "rb") as f_in, open(raw_path, "wb") as f_out:
        f_in.seek(payload_off)
        f_out.write(f_in.read())
    out.append(raw_path)
    return out
