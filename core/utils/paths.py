"""Resolve framework install paths for bundled assets and data files."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Optional


def framework_root() -> Optional[Path]:
    """Return the KittySploit framework root directory, if discoverable."""
    core_spec = importlib.util.find_spec("core")
    if core_spec and core_spec.origin:
        root = Path(core_spec.origin).resolve().parent.parent
        if (root / "core").is_dir():
            return root

    env_home = os.environ.get("KITTYSPLOIT_HOME")
    if env_home:
        root = Path(env_home).expanduser().resolve()
        if (root / "core").is_dir():
            return root

    root = Path(__file__).resolve().parents[2]
    if (root / "core").is_dir():
        return root
    return None


def require_framework_root() -> Path:
    root = framework_root()
    if root is None:
        raise FileNotFoundError("KittySploit framework root not found")
    return root


def data_dir() -> Path:
    """Return the framework data/ directory."""
    return require_framework_root() / "data"


def shared_static_img_dir() -> Path:
    """Return interfaces/static/img under the framework root."""
    return require_framework_root() / "interfaces" / "static" / "img"


def sound_notify_path() -> Optional[Path]:
    """Return notify.wav path if the notification sound asset exists."""
    path = data_dir() / "sound" / "notify.wav"
    return path if path.is_file() else None
