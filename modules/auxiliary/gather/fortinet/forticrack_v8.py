#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fortinet FortiOS 8.x firmware decryptor (forticrack_v8 workflow).

Targets kernel 4.19.13 FortiOS v8.0.0 build 0167 (FGT / FFW).
"""

from __future__ import annotations

import os

from kittysploit import *

from lib.firmware import FirmwareExtract
from lib.firmware.cpio import CpioArchive
from lib.firmware.ext2 import Ext2Reader
from lib.firmware.fortinet import FortinetFirmware, FortinetKernelProfile

# Fichiers attendus dans la partition boot FortiOS 8.x (logique module, pas lib)
_BOOT_PARTITION_FILES = ("flatkc", "rootfs.gz", "datafs.tar.gz")


class Module(Auxiliary, FirmwareExtract):
    __info__ = {
        "name": "Fortinet FortiOS 8.x Firmware Decryptor (forticrack_v8)",
        "description": (
            "Decrypt Fortinet .out firmware (FortiOS 8.0 / kernel 4.19.13 build 0167), "
            "extract flatkc and rootfs.gz from the boot partition, decrypt rootfs with "
            "RSA + FORT-RC4, and unpack the CPIO initramfs. Pure Python — no gunzip, "
            "binwalk, or cpio required."
        ),
        "author": ["@hacefresko", "Bishop Fox", "KittySploit Team"],
        "references": [
            "https://github.com/BishopFox/forticrack",
            "https://bishopfox.com/blog/breaking-fortinet-firmware-encryption",
            "https://bishopfox.com/blog/further-adventures-in-fortinet-decryption",
        ],
        "cve": "",
        "tags": ["fortinet", "fortios", "firmware", "decrypt", "forticrack"],
    }

    firmware_path = OptString(
        "",
        "Local path to the encrypted Fortinet .out firmware file",
        required=True,
    )
    variant = OptString(
        "",
        "Firmware variant: FGT or FFW (auto-detected from filename if empty)",
        required=False,
    )
    output_dir = OptString(
        "",
        "Output directory (default: <firmware_basename>_extracted next to input)",
        required=False,
        advanced=True,
    )
    skip_rootfs = OptBool(
        False,
        "Stop after boot-partition extraction (do not decrypt/unpack rootfs)",
        required=False,
        advanced=True,
    )

    def check(self):
        path = str(self.firmware_path or "").strip()
        if not path:
            print_error("firmware_path is required")
            return False
        if not os.path.isfile(path):
            print_error(f"File not found: {path}")
            return False
        if not os.access(path, os.R_OK):
            print_error(f"Not readable: {path}")
            return False
        try:
            FortinetFirmware.detect_variant(path, str(self.variant or "").strip() or None)
        except ValueError as exc:
            print_error(str(exc))
            return False
        return True

    def _resolve_output_dir(self, firmware_path: str) -> str:
        custom = str(self.output_dir or "").strip()
        if custom:
            return os.path.abspath(custom)
        base = os.path.splitext(os.path.basename(firmware_path))[0]
        parent = os.path.dirname(os.path.abspath(firmware_path))
        return os.path.join(parent, f"{base}_extracted")

    def run(self):
        firmware_path = os.path.abspath(str(self.firmware_path).strip())
        out_dir = self._resolve_output_dir(firmware_path)
        os.makedirs(out_dir, exist_ok=True)

        try:
            variant = FortinetFirmware.detect_variant(
                firmware_path, str(self.variant or "").strip() or None
            )
        except ValueError as exc:
            print_error(str(exc))
            return False

        fortinet = FortinetFirmware(
            variant=variant,
            kernel_profile=FortinetKernelProfile.default_profile(),
        )

        print_status(f"Variant: {variant}")
        print_status(f"Output directory: {out_dir}")

        print_status(f"[1] Loading {firmware_path}")
        ciphertext = FortinetFirmware.load_image(firmware_path)
        if not ciphertext:
            print_error("Failed to load firmware image data")
            return False
        print_success(f"Loaded {len(ciphertext)} bytes")

        if not fortinet.is_encrypted(ciphertext):
            print_warning("Firmware image appears to be cleartext already")
            decrypted = ciphertext
            key = None
        else:
            print_status("[1] Deriving encryption key (known-plaintext attack)")
            try:
                decrypted, key = fortinet.decrypt_image(ciphertext)
            except ValueError as exc:
                print_error(str(exc))
                return False
            print_success(f"Found key: {key.decode('ascii')}")
            print_success(f"Decrypted firmware ({len(decrypted)} bytes)")

        decrypted_path = os.path.join(out_dir, "firmware.decrypted")
        with open(decrypted_path, "wb") as f:
            f.write(decrypted)

        print_status("[2] Extracting boot partition (ext2)")
        ext_root = os.path.join(out_dir, "ext-root")
        try:
            ext2 = Ext2Reader.from_image(decrypted)
            ext2.extract_files(ext_root, _BOOT_PARTITION_FILES)
        except (ValueError, FileNotFoundError, OSError) as exc:
            print_error(f"Boot partition extraction failed: {exc}")
            return False

        if not Ext2Reader.verify_files(ext_root, _BOOT_PARTITION_FILES):
            print_error("Verification failed: flatkc, rootfs.gz, or datafs.tar.gz missing")
            return False
        print_success(f"Extracted boot files to {ext_root}")

        if self.skip_rootfs:
            print_status("skip_rootfs set — stopping before rootfs decryption")
            return True

        print_status("[3] Decrypting rootfs.gz")

        flatkc_path = os.path.join(ext_root, "flatkc")
        rootfs_path = os.path.join(ext_root, "rootfs.gz")
        with open(flatkc_path, "rb") as f:
            flatkc = f.read()
        with open(rootfs_path, "rb") as f:
            rootfs = f.read()

        try:
            kernel_elf = fortinet.extract_kernel_elf(flatkc)
        except ValueError as exc:
            print_error(f"Failed to extract kernel ELF from flatkc: {exc}")
            return False
        print_success("Extracted kernel ELF from flatkc")

        elf_path = os.path.join(ext_root, "flatkc.elf")
        with open(elf_path, "wb") as f:
            f.write(kernel_elf)

        try:
            rsa_key = fortinet.extract_rsa_key_from_elf(kernel_elf)
        except ValueError as exc:
            print_error(f"Failed to extract RSA public key: {exc}")
            return False

        n_preview = rsa_key["n"].to_bytes(256, "big")[:8].hex()
        print_success("Extracted RSA public key from kernel ELF")
        print_status(f"    n = {n_preview}... ({rsa_key['n'].bit_length()} bits)")
        print_status(f"    e = {rsa_key['e']}")

        try:
            decrypted_rootfs, signature = fortinet.decrypt_rootfs(rootfs, rsa_key)
        except ValueError as exc:
            print_error(f"Rootfs decryption failed: {exc}")
            return False

        print_success("Decrypted rootfs signature block")
        print_status(f"    RC4 key:     {signature['rc4_key'].hex()}")
        print_status(f"    SHA256 hash: {signature['sha256_in_sig'].hex()}")
        if signature.get("sha256_match"):
            print_success("Signature SHA256 matches rootfs body")
        else:
            print_warning("Signature SHA256 does not match rootfs body")

        decrypted_rootfs_path = os.path.join(ext_root, "rootfs.decrypted.gz")
        with open(decrypted_rootfs_path, "wb") as f:
            f.write(decrypted_rootfs)
        print_success("Rootfs decrypted to gzip stream")

        rootfs_extract_path = os.path.join(ext_root, "rootfs")
        print_status(f"[4] Extracting CPIO rootfs into {rootfs_extract_path}")
        try:
            count = CpioArchive.extract_from_gzip(decrypted_rootfs, rootfs_extract_path)
        except (ValueError, OSError) as exc:
            print_error(f"Rootfs CPIO extraction failed: {exc}")
            return False

        print_success(f"Rootfs extracted ({count} entries) to {rootfs_extract_path}")
        print_status(f"Artifacts: {out_dir}")
        return True
