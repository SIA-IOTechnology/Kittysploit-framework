#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Détection de signatures et décompression récursive de firmwares binaires (.bin).
Les images embarquées (TRX, uImage, etc.) placent souvent gzip/squashfs après des en-têtes :
on scanne un préfixe du fichier pour trouver la première signature connue, pas seulement l’offset 0.
"""

from __future__ import annotations

import gzip
import lzma
import os
import zlib
from typing import Any, Dict, List, Optional, Tuple

from core.output_handler import print_error, print_info, print_warning

_GZIP_READ_ERRORS: Tuple[type, ...] = (OSError, EOFError, zlib.error)
if hasattr(gzip, "BadGzipFile"):
    _GZIP_READ_ERRORS = _GZIP_READ_ERRORS + (gzip.BadGzipFile,)

SignatureEntry = Tuple[str, int]

# Types que l’on sait décompresser depuis un offset arbitraire
_DECOMPRESS_TYPES = frozenset({"gzip", "lzma", "xz"})
# Signatures « informatives » si aucune couche gzip/lzma/xz (ubifs exclu : trop de faux positifs)
_SECONDARY_TYPES = frozenset({"squashfs", "elf", "cpio"})


class PyFirmwareExtractor:
    # offset dans SIGNATURES : réservé pour extensions (ex. signature à un offset fixe connu)
    SIGNATURES: Dict[bytes, SignatureEntry] = {
        b"\x1f\x8b": ("gzip", 0),
        b"\xfd\x37\x7a\x58\x5a\x00": ("xz", 0),
        b"!\x18": ("lzma", 0),
        b"\x37\x7a\xbc\xaf\x27\x1c": ("squashfs", 0),
        b"\x68\x73\x71\x73": ("squashfs", 0),  # hsqs — squashfs 4.0
        b"sqsh": ("squashfs", 0),  # squashfs 3.x (souvent « non-standard » dans binwalk)
        b"\x71\xc7": ("cpio", 0),
        b"\x7fELF": ("elf", 0),
    }

    # En-tête TRX Broadcom / variantes (information seulement)
    _TRX_MAGIC = b"HDR0"

    def __init__(self, firmware_path: str, output_dir: Optional[str] = None) -> None:
        self.firmware_path = os.path.abspath(firmware_path)
        base = os.path.dirname(self.firmware_path)
        self.output_dir = (
            os.path.abspath(output_dir)
            if output_dir
            else os.path.join(base, "extracted")
        )
        self.max_depth = 32
        # Taille max lue pour la détection (images TRX + gzip + squashfs plus bas)
        self.scan_bytes = 8 * 1024 * 1024

    def _read_scan_data(self) -> bytes:
        try:
            size = os.path.getsize(self.firmware_path)
        except OSError:
            size = 0
        to_read = min(size, self.scan_bytes) if size else self.scan_bytes
        with open(self.firmware_path, "rb") as f:
            return f.read(to_read)

    def detect_file_type(self, data: bytes) -> str:
        """Compat : premier type trouvé en tête ou au premier offset (ancien comportement simplifié)."""
        t, _off = self.detect_file_type_at_offset(data)
        return t

    def detect_file_type_at_offset(self, data: bytes) -> Tuple[str, int]:
        """
        Trouve la première signature « utile » dans le buffer : d’abord gzip/lzma/xz
        (ordre d’offset minimal), sinon autres types connus.
        Retourne (type, offset) avec offset -1 si inconnu.
        """
        if not data:
            return ("unknown", -1)

        def earliest_in_map(
            type_filter=None,
        ) -> Optional[Tuple[int, str]]:
            best: Optional[Tuple[int, str]] = None
            for sig, (ftype, _fixed_off) in self.SIGNATURES.items():
                if type_filter is not None and ftype not in type_filter:
                    continue
                if ftype == "gzip":
                    continue
                pos = data.find(sig)
                if pos < 0:
                    continue
                if best is None or pos < best[0]:
                    best = (pos, ftype)
            return best

        # 1) Décompression prioritaire — gzip : uniquement offsets avec en-tête plausible (pas tout \x1f\x8b)
        decompress_hits: List[Tuple[int, str]] = []
        gz_list = self._gzip_candidate_offsets(data)
        if gz_list:
            decompress_hits.append((gz_list[0], "gzip"))
        for sig, (ftype, _fixed_off) in self.SIGNATURES.items():
            if ftype not in ("lzma", "xz"):
                continue
            pos = data.find(sig)
            if pos >= 0:
                decompress_hits.append((pos, ftype))
        if decompress_hits:
            decompress_hits.sort(key=lambda x: x[0])
            off, ftype = decompress_hits[0]
            return (ftype, off)

        # 2) Autres signatures (squashfs, ELF, cpio, …) au plus tôt dans le fichier
        hit = earliest_in_map(_SECONDARY_TYPES)
        if hit:
            return (hit[1], hit[0])

        return ("unknown", -1)

    def _compression_candidates(self, data: bytes) -> List[Tuple[int, str]]:
        """Liste triée des offsets compressés plausibles à tester."""
        hits: List[Tuple[int, str]] = []
        for off in self._gzip_candidate_offsets(data):
            hits.append((off, "gzip"))
        for sig, (ftype, _fixed_off) in self.SIGNATURES.items():
            if ftype not in ("lzma", "xz"):
                continue
            pos = data.find(sig)
            if pos >= 0:
                hits.append((pos, ftype))
        hits.sort(key=lambda item: item[0])
        return hits

    def _secondary_candidate(self, data: bytes) -> Tuple[str, int]:
        """Retourne la première signature informative non compressée."""
        best: Optional[Tuple[int, str]] = None
        for sig, (ftype, _fixed_off) in self.SIGNATURES.items():
            if ftype not in _SECONDARY_TYPES:
                continue
            pos = data.find(sig)
            if pos < 0:
                continue
            if best is None or pos < best[0]:
                best = (pos, ftype)
        if best is None:
            return ("unknown", -1)
        return (best[1], best[0])

    def _list_embedded_hits(self, data: bytes) -> List[Tuple[int, str]]:
        """Résumé type binwalk : (offset, type) pour gzip et squashfs dans le scan."""
        out: List[Tuple[int, str]] = []
        for sig, (ftype, _) in self.SIGNATURES.items():
            if ftype not in ("gzip", "squashfs"):
                continue
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos < 0:
                    break
                if ftype == "gzip" and not self._looks_like_gzip_header(data, pos):
                    start = pos + 1
                    continue
                out.append((pos, ftype))
                start = pos + 1
        out.sort(key=lambda x: x[0])
        return out

    @staticmethod
    def _looks_like_gzip_header(data: bytes, offset: int) -> bool:
        """Filtre les faux positifs : magic + méthode deflate (CM=8)."""
        if offset < 0 or offset + 10 > len(data):
            return False
        if data[offset : offset + 2] != b"\x1f\x8b":
            return False
        return data[offset + 2] == 8

    def _gzip_candidate_offsets(self, data: bytes) -> List[int]:
        """Offsets triés où un gzip plausible commence (pour essais multiples)."""
        out: List[int] = []
        start = 0
        while True:
            pos = data.find(b"\x1f\x8b", start)
            if pos < 0:
                break
            if self._looks_like_gzip_header(data, pos):
                out.append(pos)
            start = pos + 1
        out.sort()
        return out

    def _note_trx(self, data: bytes) -> None:
        pos = data.find(self._TRX_MAGIC)
        if pos >= 0:
            print_info(
                f"TRX-style magic {self._TRX_MAGIC!r} at offset 0x{pos:x} "
                "(firmware partition header; gzip/squashfs often follow)."
            )

    def decompress(
        self, input_path: str, output_path: str, file_type: str, offset: int = 0
    ) -> None:
        """
        Décompresse un membre gzip/lzma/xz à partir de l'offset.
        Utilise GzipFile(fileobj=...) après seek — plus fiable que gzip.open sur fichier partiel.
        """
        with open(input_path, "rb") as f_in:
            if offset:
                f_in.seek(offset)
            if file_type == "gzip":
                with gzip.GzipFile(fileobj=f_in, mode="rb") as f_gz, open(
                    output_path, "wb"
                ) as f_out:
                    f_out.write(f_gz.read())
            elif file_type in ("lzma", "xz"):
                with lzma.open(f_in) as f_lzma, open(output_path, "wb") as f_out:
                    f_out.write(f_lzma.read())
            else:
                raise ValueError(f"Unsupported compression: {file_type}")

    def _try_decompress_with_candidates(
        self,
        file_type: str,
        data: bytes,
        preferred_offset: int,
        output_path: str,
    ) -> int:
        """
        Tente la décompression ; pour gzip, essaie plusieurs offsets plausibles si besoin.
        Retourne l'offset ayant fonctionné, ou lève la dernière exception.
        """
        if file_type != "gzip":
            self.decompress(self.firmware_path, output_path, file_type, offset=preferred_offset)
            return preferred_offset

        candidates = self._gzip_candidate_offsets(data)
        if preferred_offset in candidates:
            ordered = [preferred_offset] + [o for o in candidates if o != preferred_offset]
        else:
            ordered = [preferred_offset] + candidates

        seen: set = set()
        ordered_unique = []
        for o in ordered:
            if o in seen:
                continue
            seen.add(o)
            ordered_unique.append(o)

        last_exc: Optional[BaseException] = None
        for off in ordered_unique[:48]:
            try:
                self.decompress(self.firmware_path, output_path, file_type, offset=off)
                with open(output_path, "rb") as fchk:
                    chunk = fchk.read(1)
                if not chunk:
                    raise OSError("decompressed output is empty")
                if off != preferred_offset:
                    print_info(f"Gzip decompression succeeded at alternate offset 0x{off:x}")
                return off
            except _GZIP_READ_ERRORS as e:
                last_exc = e
                print_warning(f"gzip (GzipFile) at 0x{off:x}: {e}")
            except Exception as e:
                last_exc = e
                print_warning(f"gzip (GzipFile) at 0x{off:x}: {e}")
            # Repli zlib : certains firmwares / membres « piggy » passent mieux avec zlib + wbits gzip
            if self._decompress_gzip_zlib_fallback(off, output_path):
                print_info(
                    f"Gzip decompression succeeded via zlib fallback at offset 0x{off:x}"
                )
                return off

        if last_exc is not None:
            raise last_exc
        raise OSError("no gzip candidate produced output")

    def _decompress_gzip_zlib_fallback(self, offset: int, output_path: str) -> bool:
        """Décompresse un membre gzip avec zlib.decompress (parfois tolérant là où GzipFile échoue)."""
        with open(self.firmware_path, "rb") as f:
            f.seek(offset)
            raw = f.read()
        if len(raw) < 10:
            return False
        try:
            out = zlib.decompress(raw, wbits=16 + zlib.MAX_WBITS)
        except zlib.error:
            return False
        if not out:
            return False
        with open(output_path, "wb") as f:
            f.write(out)
        return True

    def extract(self, _depth: int = 0) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "file_type": "unknown",
            "signature_offset": -1,
            "output_dir": self.output_dir,
            "decompressed_path": None,
            "nested": None,
            "error": None,
        }

        if _depth >= self.max_depth:
            print_warning(
                f"Firmware extract: max depth ({self.max_depth}) reached, stopping."
            )
            return result

        os.makedirs(self.output_dir, exist_ok=True)
        data = self._read_scan_data()
        self._note_trx(data)

        file_type, sig_offset = self.detect_file_type_at_offset(data)
        result["file_type"] = file_type
        result["signature_offset"] = sig_offset

        embedded = self._list_embedded_hits(data)
        if len(embedded) > 1:
            summary = ", ".join(
                f"0x{off:x}={typ}" for off, typ in embedded[:8]
            )
            if len(embedded) > 8:
                summary += ", …"
            print_info(
                f"Multiple gzip/squashfs regions in scan range ({summary}). "
                "Processing earliest decompressible stream; full carving may need binwalk."
            )

        if sig_offset >= 0:
            print_info(
                f"Detected file type: {file_type} at offset 0x{sig_offset:x} ({sig_offset})"
            )
        else:
            print_info(f"Detected file type: {file_type}")

        if file_type in _DECOMPRESS_TYPES and sig_offset >= 0:
            output_path = os.path.join(self.output_dir, "decompressed.bin")
            compression_candidates = self._compression_candidates(data)
            if sig_offset >= 0 and (sig_offset, file_type) in compression_candidates:
                ordered_candidates = [(sig_offset, file_type)] + [
                    item
                    for item in compression_candidates
                    if item != (sig_offset, file_type)
                ]
            else:
                ordered_candidates = compression_candidates

            last_error: Optional[Exception] = None
            for candidate_offset, candidate_type in ordered_candidates:
                try:
                    used_offset = self._try_decompress_with_candidates(
                        candidate_type, data, candidate_offset, output_path
                    )
                    result["file_type"] = candidate_type
                    result["signature_offset"] = used_offset
                    print_info(f"Decompressed to: {output_path}")
                    result["decompressed_path"] = output_path
                    sub_extractor = PyFirmwareExtractor(output_path)
                    sub_extractor.max_depth = self.max_depth
                    sub_extractor.scan_bytes = self.scan_bytes
                    result["nested"] = sub_extractor.extract(_depth=_depth + 1)
                    break
                except Exception as e:
                    last_error = e
                    print_warning(
                        f"Skipping invalid {candidate_type} stream at 0x{candidate_offset:x}: {e}"
                    )

            if result["decompressed_path"] is None:
                result["error"] = str(last_error) if last_error else "decompression failed"
                secondary_type, secondary_offset = self._secondary_candidate(data)
                if secondary_offset >= 0:
                    result["file_type"] = secondary_type
                    result["signature_offset"] = secondary_offset
                    print_info(
                        f"Falling back to detected {secondary_type} at offset "
                        f"0x{secondary_offset:x} ({secondary_offset})"
                    )
                    if secondary_type == "squashfs":
                        print_info(
                            f"SquashFS detected at offset 0x{secondary_offset:x} "
                            f"(output dir {self.output_dir}) — "
                            "extraction not implemented (e.g. unsquashfs / carve at offset)."
                        )
                    elif secondary_type == "elf":
                        print_info(
                            "ELF binary detected after failed decompression attempts — "
                            "no automatic unpack in this module."
                        )
                else:
                    print_error(f"Decompression failed: {result['error']}")
        elif file_type == "squashfs":
            print_info(
                f"SquashFS detected at offset 0x{sig_offset:x} "
                f"(output dir {self.output_dir}) — "
                "extraction not implemented (e.g. unsquashfs / carve at offset)."
            )
        elif file_type == "elf":
            print_info("ELF binary detected — no automatic unpack in this module.")
        else:
            print_info(f"Unknown or unsupported file type: {file_type}")

        return result
