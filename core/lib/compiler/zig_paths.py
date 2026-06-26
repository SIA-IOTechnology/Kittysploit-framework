#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve the Zig compiler executable (PATH or bundled install)."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path
from typing import Optional

from core.utils.paths import framework_root


def find_zig_executable() -> Optional[str]:
    """Return the path to a working Zig executable, or None if not found."""
    for candidate in ("zig", "zig.exe"):
        if shutil.which(candidate):
            return candidate

    root = framework_root()
    if root is None:
        return None

    bundled = root / "core" / "lib" / "compiler" / "zig_executable" / (
        "zig.exe" if platform.system() == "Windows" else "zig"
    )
    if bundled.is_file() and (bundled.parent / "lib").is_dir():
        return str(bundled)
    return None
