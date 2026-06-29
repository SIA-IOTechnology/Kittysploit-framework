#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extraction et détection de formats firmware (TRX, gzip, lzma/xz, ELF, ext2, CPIO).
"""

from lib.firmware.cpio import CpioArchive
from lib.firmware.ext2 import Ext2Reader
from lib.firmware.extract import (
    FirmwareExtract,
    decompress_gzip_bytes,
    extract_elf,
    extract_gzip,
    extract_lzma,
    load_maybe_gzip_file,
)
from lib.firmware.fortinet import FortinetFirmware, FortinetKernelProfile
from lib.firmware.trx import extract_trx
from lib.firmware.utils import SUPPORTED_FORMATS_DEFAULT, detect_firmware_type

__all__ = [
    "FirmwareExtract",
    "CpioArchive",
    "Ext2Reader",
    "FortinetFirmware",
    "FortinetKernelProfile",
    "decompress_gzip_bytes",
    "load_maybe_gzip_file",
    "detect_firmware_type",
    "extract_trx",
    "extract_gzip",
    "extract_lzma",
    "extract_elf",
    "SUPPORTED_FORMATS_DEFAULT",
]
