#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *

from lib.analysis.binary.firmware_extractor import PyFirmwareExtractor


class Module(Auxiliary):
    __info__ = {
        "name": "Firmware .bin signature scan and decompress",
        "description": (
            "Detects common firmware signatures (gzip, lzma, xz, squashfs, ELF, etc.) "
            "on a local file and recursively decompresses supported compressed formats."
        ),
        "author": "KittySploit Team",
        "references": [],
        "cve": "",
        "tags": ["firmware", "binary", "analysis", "gzip", "squashfs"],
    }

    firmware = OptString(
        "",
        "Local filesystem path to the firmware .bin file",
        required=True,
    )
    output_dir = OptString(
        "",
        "Output directory for extracted data (default: <firmware_dir>/extracted)",
        required=False,
        advanced=True,
    )
    max_depth = OptInteger(
        32,
        "Max recursive decompression depth",
        required=False,
        advanced=True,
    )

    def check(self):
        path = self.firmware or ""
        path = str(path).strip()
        if not path:
            print_error("firmware option is required")
            return False
        if not os.path.isfile(path):
            print_error(f"File not found: {path}")
            return False
        if not os.access(path, os.R_OK):
            print_error(f"Not readable: {path}")
            return False
        return True

    def run(self):
        path = os.path.abspath(str(self.firmware or "").strip())
        out = str(self.output_dir).strip() if self.output_dir else ""
        extractor = PyFirmwareExtractor(path, output_dir=out or None)
        try:
            extractor.max_depth = int(self.max_depth)
        except (TypeError, ValueError):
            extractor.max_depth = 32
        extractor.extract()
