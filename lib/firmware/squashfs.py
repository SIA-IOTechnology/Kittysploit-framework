#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extraction SquashFS (unsquashfs) ou export brut du blob embarqué.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import List


def extract_squashfs(firmware_path: str, output_dir: str, offset: int = 0) -> List[str]:
    """
    Décompresse un SquashFS à ``offset`` via ``unsquashfs`` si disponible,
    sinon écrit un fichier image brut pour analyse offline.
    """
    os.makedirs(output_dir, exist_ok=True)
    dest = os.path.join(output_dir, f"squashfs_{offset:x}")
    unsquashfs = shutil.which("unsquashfs")

    if unsquashfs:
        os.makedirs(dest, exist_ok=True)
        cmd = [
            unsquashfs,
            "-force",
            "-dest",
            dest,
            "-offset",
            str(int(offset)),
            firmware_path,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        except OSError as exc:
            raise ValueError(f"unsquashfs failed: {exc}") from exc
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            raise ValueError(err or f"unsquashfs exit {proc.returncode}")

        extracted: List[str] = []
        for root, _dirs, files in os.walk(dest):
            for name in files:
                extracted.append(os.path.join(root, name))
        if not extracted:
            return [dest]
        return sorted(extracted)

    raw_path = os.path.join(output_dir, f"squashfs_{offset:x}.img")
    with open(firmware_path, "rb") as src:
        src.seek(int(offset))
        blob = src.read()
    if len(blob) < 4:
        raise ValueError("squashfs region too small")
    with open(raw_path, "wb") as out:
        out.write(blob)
    return [raw_path]
