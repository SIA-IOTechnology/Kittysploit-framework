#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extraction et détection de formats firmware (TRX, gzip, lzma/xz, ELF).
Import typique : ``from lib.firmware import detect_firmware_type, extract_gzip, extract_trx``.
"""

from lib.firmware.extract import extract_elf, extract_gzip, extract_lzma
from lib.firmware.trx import extract_trx
from lib.firmware.utils import SUPPORTED_FORMATS_DEFAULT, detect_firmware_type

__all__ = [
    "detect_firmware_type",
    "extract_trx",
    "extract_gzip",
    "extract_lzma",
    "extract_elf",
    "SUPPORTED_FORMATS_DEFAULT",
]
