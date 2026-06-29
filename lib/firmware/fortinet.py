#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Outils Fortinet pour images firmware (.out) et rootfs chiffrés.

Lib vendor-specific (Fortinet), indépendante des modules/CVE individuels.
"""

from __future__ import annotations

import hashlib
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional, Tuple

from lib.firmware.extract import FirmwareExtract


def _decrypt_image_block_worker(args: Tuple[bytes, bytes]) -> bytes:
    block, key = args
    return FortinetFirmware().decrypt_block(block, key)


@dataclass(frozen=True)
class FortinetKernelProfile:
    """Offsets kernel ELF pour l'extraction de clé RSA embarquée."""

    name: str
    segments: Tuple[Tuple[int, int, int], ...]
    rsa_enc_va: int
    rsa_enc_len: int
    xor_key_va: int

    def va_to_offset(self, va: int) -> Optional[int]:
        for vaddr, foff, fsz in self.segments:
            if vaddr <= va < vaddr + fsz:
                return foff + (va - vaddr)
        return None

    @staticmethod
    def default_profile() -> "FortinetKernelProfile":
        """Profil kernel 4.19.13 FortiOS v8.0.0 build 0167 (FGT / FFW)."""
        return FortinetKernelProfile(
            name="4.19.13-v8.0.0-build-0167",
            segments=(
                (0xFFFFFFFF80200000, 0x200000, 0x12FA000),
                (0xFFFFFFFF81600000, 0x1600000, 0xE5000),
                (0x0000000000000000, 0x1800000, 0x29000),
                (0xFFFFFFFF8170E000, 0x190E000, 0x12E000),
            ),
            rsa_enc_va=0xFFFFFFFF8179A1A0,
            rsa_enc_len=0x10E,
            xor_key_va=0xFFFFFFFF8179A2C0,
        )


class FortinetFirmware:
    """
    Déchiffrement d'images Fortinet (.out) et rootfs (RSA + FORT-RC4).

    Usage typique dans un module :
        fw = FortinetFirmware(variant="FGT")
        raw = FortinetFirmware.load_image(path)
        decrypted, key = fw.decrypt_image(raw)
    """

    BLOCK_SIZE = 512
    FIRMWARE_MAGIC = b"\xff\x00\xaa\x55"
    GZIP_MAGIC = b"\x1f\x8b"
    SIGNATURE_SIZE = 256

    def __init__(
        self,
        variant: str = "FGT",
        kernel_profile: Optional[FortinetKernelProfile] = None,
        max_workers: Optional[int] = None,
    ) -> None:
        variant = (variant or "FGT").strip().upper()
        if variant not in ("FGT", "FFW"):
            raise ValueError("variant must be FGT or FFW")
        self.variant = variant
        self.kernel_profile = kernel_profile or FortinetKernelProfile.default_profile()
        self.max_workers = max_workers

    @staticmethod
    def detect_variant(path: str, variant: Optional[str] = None) -> str:
        if variant:
            v = variant.strip().upper()
            if v not in ("FGT", "FFW"):
                raise ValueError("variant must be FGT or FFW")
            return v

        upper = path.upper()
        if "FGT" in upper:
            return "FGT"
        if "FFW" in upper:
            return "FFW"
        raise ValueError("could not determine FGT/FFW variant — set variant explicitly")

    @staticmethod
    def load_image(path: str) -> Optional[bytes]:
        return FirmwareExtract.load_maybe_gzip_file(path)

    @classmethod
    def validate_key(cls, key: bytes) -> bool:
        if len(key) != 32:
            return False
        try:
            string = key.decode("ascii")
        except UnicodeDecodeError:
            return False
        return all(re.match(r"[0-9A-Za-z]", char) for char in string)

    @classmethod
    def derive_key_byte(
        cls,
        key_offset: int,
        ciphertext_byte: int,
        previous_ciphertext_byte: int,
        known_plaintext: int,
    ) -> int:
        key_byte = (
            previous_ciphertext_byte ^ (known_plaintext + key_offset) ^ ciphertext_byte
        )
        return (key_byte + 256) & 0xFF

    def decrypt_block(
        self, ciphertext: bytes, key: bytes, num_bytes: Optional[int] = None
    ) -> bytes:
        if num_bytes is None or num_bytes > len(ciphertext):
            num_bytes = len(ciphertext)
        if num_bytes > self.BLOCK_SIZE:
            num_bytes = self.BLOCK_SIZE

        key_offset = 0
        block_offset = 0
        cleartext = bytearray()
        previous_ciphertext_byte = 0xFF

        while block_offset < num_bytes:
            if key_offset >= len(key):
                return bytes(cleartext)

            ciphertext_byte = ciphertext[block_offset]
            xor = (
                previous_ciphertext_byte ^ ciphertext_byte ^ key[key_offset]
            ) - key_offset
            cleartext.append((xor + 256) & 0xFF)

            block_offset += 1
            key_offset = (key_offset + 1) & 0x1F
            previous_ciphertext_byte = ciphertext_byte

        return bytes(cleartext)

    @classmethod
    def validate_header(cls, cleartext: bytes) -> bool:
        if len(cleartext) < 80 or cleartext[12:16] != cls.FIRMWARE_MAGIC:
            return False
        try:
            image_name = cleartext[16:46].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return False
        return "build" in image_name.lower()

    @classmethod
    def derive_block_key(cls, ciphertext: bytes) -> Optional[bytes]:
        key = bytearray()
        known_plaintext = 0x00

        for i in range(32):
            key_offset = (i + 16) % 32
            plaintext_offset = i + 48
            key.append(
                cls.derive_key_byte(
                    key_offset,
                    ciphertext[plaintext_offset],
                    ciphertext[plaintext_offset - 1],
                    known_plaintext,
                )
            )
        key = key[16:] + key[:16]

        if not cls.validate_key(bytes(key)):
            return None

        instance = cls()
        cleartext = instance.decrypt_block(ciphertext, bytes(key))
        if cls.validate_header(cleartext):
            return bytes(key)
        return None

    def derive_image_key(self, ciphertext: bytes) -> Optional[bytes]:
        num_blocks = (len(ciphertext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        block_header_size = 80
        headers = [
            ciphertext[
                block_num * self.BLOCK_SIZE : block_num * self.BLOCK_SIZE + block_header_size
            ]
            for block_num in range(num_blocks)
        ]
        if not headers:
            return None

        with ProcessPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(self.derive_block_key, header) for header in headers]
            for future in as_completed(futures):
                key = future.result()
                if key:
                    try:
                        pool.shutdown(wait=False, cancel_futures=True)
                    except TypeError:
                        pool.shutdown(wait=False)
                    return key
        return None

    def decrypt_image_blocks(self, ciphertext: bytes, key: bytes) -> bytes:
        num_blocks = (len(ciphertext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        blocks = [
            ciphertext[
                block_num * self.BLOCK_SIZE : block_num * self.BLOCK_SIZE + self.BLOCK_SIZE
            ]
            for block_num in range(num_blocks)
        ]

        with ProcessPoolExecutor(max_workers=self.max_workers) as pool:
            results = list(pool.map(_decrypt_image_block_worker, ((block, key) for block in blocks)))
        return b"".join(results)

    def is_encrypted(self, ciphertext: bytes) -> bool:
        for block_offset in range(0, len(ciphertext), self.BLOCK_SIZE):
            if self.validate_header(ciphertext[block_offset : block_offset + 80]):
                return False
        return True

    def decrypt_image(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        key = self.derive_image_key(ciphertext)
        if not key:
            raise ValueError("no valid firmware encryption key found")
        return self.decrypt_image_blocks(ciphertext, key), key

    @staticmethod
    def parse_rsa_der(data: bytes) -> dict:
        def read_tl(d: bytes, p: int):
            tag = d[p]
            p += 1
            length = d[p]
            p += 1
            if length & 0x80:
                nb = length & 0x7F
                length = int.from_bytes(d[p : p + nb], "big")
                p += nb
            return tag, length, p

        tag, _, pos = read_tl(data, 0)
        if tag != 0x30:
            raise ValueError(f"expected SEQUENCE, got 0x{tag:02x}")

        tag2, l2, pos2 = read_tl(data, pos)
        if tag2 != 0x02:
            raise ValueError(f"expected INTEGER for n, got 0x{tag2:02x}")

        n_bytes = data[pos2 : pos2 + l2]
        if n_bytes[0] == 0:
            n_bytes = n_bytes[1:]
        n = int.from_bytes(n_bytes, "big")
        pos2 += l2

        tag3, l3, pos3 = read_tl(data, pos2)
        if tag3 != 0x02:
            raise ValueError(f"expected INTEGER for e, got 0x{tag3:02x}")
        e = int.from_bytes(data[pos3 : pos3 + l3], "big")
        return {"n": n, "e": e}

    def extract_rsa_key_from_elf(self, elf_data: bytes) -> dict:
        if elf_data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file — pass decompressed kernel ELF, not raw bzImage")

        profile = self.kernel_profile
        enc_off = profile.va_to_offset(profile.rsa_enc_va)
        key_off = profile.va_to_offset(profile.xor_key_va)
        if enc_off is None or key_off is None:
            raise ValueError("RSA key virtual addresses not found in ELF segments")
        if enc_off + profile.rsa_enc_len > len(elf_data) or key_off + 32 > len(elf_data):
            raise ValueError("ELF too small for embedded RSA key material")

        xor_enc = elf_data[enc_off : enc_off + profile.rsa_enc_len]
        xor_key = elf_data[key_off : key_off + 32]
        decoded = bytes(xor_enc[i] ^ xor_key[i & 0x1F] for i in range(profile.rsa_enc_len))
        return self.parse_rsa_der(decoded)

    def extract_kernel_elf(self, flatkc: bytes) -> bytes:
        offset = flatkc.find(self.GZIP_MAGIC)
        if offset < 0:
            raise ValueError("no gzip magic found in flatkc")
        return FirmwareExtract.decompress_gzip_bytes(flatkc, offset)

    @staticmethod
    def rsa_unpack_signature(sig_block_256: bytes, rsa_key: dict) -> dict:
        n, e = rsa_key["n"], rsa_key["e"]
        sig_int = int.from_bytes(sig_block_256, "big")
        if sig_int >= n:
            raise ValueError("signature integer >= modulus")

        result = pow(sig_int, e, n).to_bytes(256, "big")

        if result[0x00] != 0x00:
            raise ValueError(f"m[0x00] = 0x{result[0x00]:02x}, expected 0x00")
        if result[0x01] != 0x01:
            raise ValueError(f"m[0x01] = 0x{result[0x01]:02x}, expected 0x01")
        if not all(b == 0xFF for b in result[0x02:0x9F]):
            raise ValueError("padding bytes m[0x02..0x9E] are not all 0xFF")
        if result[0x9F] != 0x00:
            raise ValueError(f"m[0x9F] = 0x{result[0x9F]:02x}, expected 0x00")

        return {
            "sha256_in_sig": result[0xA0:0xC0],
            "rc4_key": result[0xE0:0x100],
        }

    @classmethod
    def fort_rc4_decrypt(cls, key_bytes: bytes, ciphertext: bytes, variant: str) -> bytes:
        s_box = list(range(256))
        key = list(key_bytes)
        klen = len(key)
        reset_j = variant.upper() == "FGT"

        j = 0
        for i in range(256):
            j = (j + s_box[i] + key[i % klen]) & 0xFF
            s_box[i], s_box[j] = s_box[j], s_box[i]

        i = 0
        if reset_j:
            j = 0

        result = bytearray(len(ciphertext))
        for k in range(len(ciphertext)):
            i = (i + 1) & 0xFF
            si = s_box[i]
            j = (j + si) & 0xFF
            sj = s_box[j]
            s_box[i], s_box[j] = sj, si

            t1 = (si + sj) & 0xFF
            idx1 = ((i << 5) ^ (j >> 3)) & 0xFF
            idx2 = ((j << 5) ^ (i >> 3)) & 0xFF
            mixidx = ((s_box[idx2] + s_box[idx1]) ^ 0xAA) & 0xFF
            b_var9 = (s_box[t1] + s_box[mixidx]) & 0xFF
            u_var7 = (sj + j) & 0xFF

            result[k] = ciphertext[k] ^ (b_var9 ^ s_box[u_var7])

        return bytes(result)

    def decrypt_rootfs(self, rootfs: bytes, rsa_key: dict) -> Tuple[bytes, dict]:
        if len(rootfs) < self.SIGNATURE_SIZE:
            raise ValueError("rootfs payload too small for signature block")

        rootfs_body = rootfs[: -self.SIGNATURE_SIZE]
        rootfs_sig = rootfs[-self.SIGNATURE_SIZE :]
        signature = self.rsa_unpack_signature(rootfs_sig, rsa_key)

        computed_sha = hashlib.sha256(rootfs_body).digest()
        signature["sha256_match"] = signature["sha256_in_sig"] == computed_sha

        decrypted = self.fort_rc4_decrypt(signature["rc4_key"], rootfs_body, self.variant)
        if decrypted[:2] != self.GZIP_MAGIC:
            raise ValueError("rootfs decryption failed — output is not gzip")

        return decrypted, signature
