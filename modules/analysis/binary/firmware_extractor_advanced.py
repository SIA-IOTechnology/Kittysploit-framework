#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module avancé : détection multi-formats (TRX, gzip, lzma, ELF, squashfs) et extraction
via ``lib.firmware`` (handlers dédiés, rapport).
"""

import os
import tempfile

from kittysploit import *

from lib.firmware import (
    detect_firmware_type,
    extract_elf,
    extract_gzip,
    extract_lzma,
    extract_trx,
)
from lib.firmware.utils import (
    SUPPORTED_FORMATS_DEFAULT,
    filter_gzip_redundant_with_trx,
)


class Module(Auxiliary):
    __info__ = {
        "name": "Firmware Extractor (Advanced)",
        "description": (
            "Scan and extract firmware images: TRX headers, gzip/lzma layers, ELF blobs, "
            "squashfs detection (extraction squashfs non implémentée). "
            "Nested structures are partially handled (TRX → gzip)."
        ),
        "author": ["KittySploit Team"],
        "references": [],
        "cve": "",
        "tags": ["firmware", "binary", "trx", "gzip", "analysis"],
    }

    SUPPORTED_FORMATS = {
        "trx": {**SUPPORTED_FORMATS_DEFAULT["trx"], "handler": extract_trx},
        "gzip": {**SUPPORTED_FORMATS_DEFAULT["gzip"], "handler": extract_gzip},
        "lzma": {**SUPPORTED_FORMATS_DEFAULT["lzma"], "handler": extract_lzma},
        "elf": {**SUPPORTED_FORMATS_DEFAULT["elf"], "handler": extract_elf},
        "squashfs": {**SUPPORTED_FORMATS_DEFAULT["squashfs"], "handler": None},
    }

    firmware_path = OptString(
        "",
        "Path to firmware file",
        required=True,
    )
    output_dir = OptString(
        "",
        "Output directory (default: auto temp under system temp)",
        required=False,
        advanced=True,
    )
    force_format = OptString(
        "",
        "Force single format: trx, gzip, lzma, elf (empty = auto)",
        required=False,
        advanced=True,
    )
    scan_mb = OptInteger(
        8,
        "Megabytes read from the start of the file for signature scan",
        required=False,
        advanced=True,
    )

    def check(self):
        path = str(self.firmware_path or "").strip()
        if not path:
            print_error("firmware_path is required")
            return False
        if not os.path.isfile(path):
            print_error(f"Firmware not found: {path}")
            return False
        return True

    def run(self):
        firmware_path = os.path.abspath(str(self.firmware_path).strip())
        out = str(self.output_dir or "").strip()
        output_dir = out if out else tempfile.mkdtemp(prefix="kittysploit_firmware_")
        os.makedirs(output_dir, exist_ok=True)

        try:
            mb = int(self.scan_mb)
        except (TypeError, ValueError):
            mb = 8
        max_read = max(1, mb) * 1024 * 1024

        with open(firmware_path, "rb") as f:
            data = f.read(max_read)

        print_status(f"Scanning firmware: {firmware_path}")
        detected_structure = []
        extracted_files = []
        suggestions = []

        force = str(self.force_format or "").strip().lower()
        fmt_cfg = {
            k: {a: b for a, b in v.items() if a != "handler"}
            for k, v in self.SUPPORTED_FORMATS.items()
        }

        if not force:
            detected = detect_firmware_type(data, fmt_cfg)
            detected = filter_gzip_redundant_with_trx(detected)
            if not detected:
                print_error("No supported firmware format detected in scan range.")
                return
            pairs = detected
        else:
            if force not in self.SUPPORTED_FORMATS:
                print_error(f"Unsupported format: {force}")
                return
            cfg = self.SUPPORTED_FORMATS[force]
            if force in ("gzip", "lzma", "squashfs") and cfg.get("scan"):
                sub = detect_firmware_type(data, {force: fmt_cfg[force]})
                if not sub:
                    print_error(f"No {force} match in scan range.")
                    return
                pairs = sub
            else:
                pairs = [(force, int(cfg.get("offset", 0)))]

        for fmt, offset in pairs:
            self._handle_format(
                firmware_path,
                output_dir,
                fmt,
                offset,
                detected_structure,
                extracted_files,
                suggestions,
            )

        self._generate_report(output_dir, detected_structure, extracted_files, suggestions)

    def _handle_format(
        self,
        firmware_path,
        output_dir,
        fmt,
        offset,
        detected_structure,
        extracted_files,
        suggestions,
    ):
        cfg = self.SUPPORTED_FORMATS.get(fmt)
        if not cfg:
            print_warning(f"Unknown format key: {fmt}")
            return
        handler = cfg.get("handler")
        if not handler:
            print_warning(
                f"Format {fmt} at 0x{offset:x} — extraction not implemented (e.g. unsquashfs)."
            )
            detected_structure.append({"format": fmt, "offset": offset, "handler": None})
            return

        print_info(f"Detected {fmt} at offset 0x{offset:x}")
        detected_structure.append(
            {"format": fmt, "offset": offset, "handler": handler.__name__}
        )
        try:
            extracted = handler(firmware_path, output_dir, offset)
            if extracted:
                extracted_files.extend(extracted)
                if fmt == "elf":
                    suggestions.append(
                        f"Use core ELF analyzer / tools on: {extracted[0]}"
                    )
        except Exception as e:
            print_error(f"Failed to extract {fmt}: {e}")

    def _generate_report(self, output_dir, detected_structure, extracted_files, suggestions):
        print_info("\n=== Firmware Extraction Report ===")
        print_info("Detected structure:")
        for item in detected_structure:
            h = item.get("handler")
            print_info(f"  - {item['format']} at 0x{item['offset']:x} ({h})")

        print_info("\nExtracted files:")
        for fpath in extracted_files:
            print_success(f"  - {fpath}")

        if suggestions:
            print_info("\nSuggestions for next steps:")
            for s in suggestions:
                print_info(f"  - {s}")

        report_path = os.path.join(output_dir, "extraction_report.txt")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("=== Firmware Extraction Report ===\n")
                f.write("Detected structure:\n")
                for item in detected_structure:
                    f.write(
                        f"  - {item['format']} at 0x{item['offset']:x}\n"
                    )
                f.write("\nExtracted files:\n")
                for fp in extracted_files:
                    f.write(f"  - {fp}\n")
                if suggestions:
                    f.write("\nSuggestions:\n")
                    for s in suggestions:
                        f.write(f"  - {s}\n")
            print_success(f"Report saved to: {report_path}")
        except OSError as e:
            print_warning(f"Could not write report: {e}")
