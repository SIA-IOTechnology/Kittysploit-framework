"""Resolve official marketplace UI apps."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Dict, Optional

from core.utils.paths import framework_root, shared_static_img_dir

# extension id -> python package directory name under src/
OFFICIAL_APP_PACKAGES: Dict[str, str] = {
    "kittyproxy": "kittyproxy",
    "kittyosint": "kittyosint",
    "kittyprotocol": "kittyprotocol",
    "kittycluster": "kittycluster",
}


def discover_app_src(root: Path, package_name: str) -> Optional[Path]:
    extensions = root / "extensions"
    if extensions.is_dir():
        for src_dir in sorted(extensions.glob("**/src")):
            if (src_dir / package_name / "__init__.py").is_file():
                return src_dir

    apps_root = root / "apps"
    if apps_root.is_dir():
        for app_dir in sorted(apps_root.iterdir()):
            if not app_dir.is_dir():
                continue
            src = app_dir / "src"
            if (src / package_name / "__init__.py").is_file():
                return src

    return None


def _load_package(package_name: str, src: Path) -> None:
    pkg_dir = src / package_name
    init_file = pkg_dir / "__init__.py"
    if not init_file.is_file():
        return

    existing = sys.modules.get(package_name)
    if existing is not None and hasattr(existing, "__path__"):
        return
    if existing is not None:
        del sys.modules[package_name]

    spec = importlib.util.spec_from_file_location(
        package_name,
        str(init_file),
        submodule_search_locations=[str(pkg_dir)],
    )
    if spec is None or spec.loader is None:
        return

    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)


def ensure_app_path(app_id: str) -> bool:
    """Add an official app package to sys.path. Returns True if importable."""
    package_name = OFFICIAL_APP_PACKAGES.get(app_id)
    if not package_name:
        return False

    root = framework_root()
    if root is None:
        return False

    src = discover_app_src(root, package_name)
    if src is None:
        return False

    src_str = str(src)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)

    root_str = str(root)
    if root_str not in sys.path:
        sys.path.append(root_str)

    _load_package(package_name, src)
    return importlib.util.find_spec(package_name) is not None


def install_hint(app_id: str) -> str:
    return f"Install with: market install {app_id}  (or: market install ./apps/{app_id})"
