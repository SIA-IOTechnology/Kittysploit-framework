"""Resolve framework install paths for bundled assets and data files."""

from __future__ import annotations

import importlib.util
import os
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Iterator, Optional

_DATA_PACKAGE = "data"
_INTERFACES_STATIC_PACKAGE = "interfaces.static"
_CORE_PACKAGE = "core"


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


def _resource_path(package: str, *parts: str):
    return resources.files(package).joinpath(*parts)


def _resource_exists(package: str, *parts: str) -> bool:
    try:
        return _resource_path(package, *parts).is_file()
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        return False


def _resource_fs_path(package: str, *parts: str) -> Optional[Path]:
    if not _resource_exists(package, *parts):
        return None
    candidate = Path(str(_resource_path(package, *parts)))
    return candidate if candidate.is_file() else None


@contextmanager
def _resource_as_file(package: str, *parts: str) -> Iterator[Path]:
    ref = _resource_path(package, *parts)
    with resources.as_file(ref) as path:
        yield Path(path)


def data_resource(*parts: str):
    return _resource_path(_DATA_PACKAGE, *parts)


def data_resource_exists(*parts: str) -> bool:
    """Return True when a bundled file exists under data/."""
    return _resource_exists(_DATA_PACKAGE, *parts)


def read_data_text(*parts: str, encoding: str = "utf-8", errors: str = "strict") -> str:
    return data_resource(*parts).read_text(encoding=encoding, errors=errors)


def read_data_lines(*parts: str, encoding: str = "utf-8", errors: str = "ignore") -> list[str]:
    return [line for line in read_data_text(*parts, encoding=encoding, errors=errors).splitlines() if line.strip()]


def data_resource_fs_path(*parts: str) -> Optional[Path]:
    """Return a filesystem path when a bundled data file is available on disk."""
    return _resource_fs_path(_DATA_PACKAGE, *parts)


@contextmanager
def data_resource_as_file(*parts: str) -> Iterator[Path]:
    """Yield a filesystem path for a bundled data file (extracts when needed)."""
    with _resource_as_file(_DATA_PACKAGE, *parts) as path:
        yield path


def data_dir() -> Path:
    return require_framework_root() / "data"


def static_resource(*parts: str):
    return _resource_path(_INTERFACES_STATIC_PACKAGE, *parts)


def shared_static_img_dir() -> Path:
    static_img = static_resource("img")
    candidate = Path(str(static_img))
    if candidate.is_dir():
        return candidate
    return require_framework_root() / "interfaces" / "static" / "img"


def core_resource(*parts: str):
    return _resource_path(_CORE_PACKAGE, *parts)


def read_core_text(*parts: str, encoding: str = "utf-8", errors: str = "strict") -> str:
    return core_resource(*parts).read_text(encoding=encoding, errors=errors)


def sound_notify_path() -> Optional[Path]:
    """Return notify.wav path if the notification sound asset exists."""
    return data_resource_fs_path("sound", "notify.wav")
