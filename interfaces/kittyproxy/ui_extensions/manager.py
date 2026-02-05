"""
Manager for KittyProxy UI extensions.

UI extensions add new tabs in the interface, each with its own HTML/JS/CSS
(like Burp Suite extensions). They do NOT modify proxy behavior.

Each extension is a folder containing:
  - manifest.json: id, name, tabLabel, icon (Material symbol name), entry (e.g. index.html)
  - entry file and any other static assets

Directories scanned (in order):
  1. Built-in: interfaces/kittyproxy/ui_extensions/
  2. User: KITTYPROXY_UI_EXTENSIONS env var, or ~/.kittyproxy/ui_extensions/
"""

import os
import json
import re
from typing import List, Dict, Any, Optional

# Built-in extensions (next to this file)
BUILTIN_DIR = os.path.join(os.path.dirname(__file__))

# Safe id: only alphanumeric and underscore
ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


def _user_extensions_dir() -> Optional[str]:
    path = os.environ.get("KITTYPROXY_UI_EXTENSIONS")
    if path and os.path.isdir(path):
        return path
    home = os.path.expanduser("~")
    default = os.path.join(home, ".kittyproxy", "ui_extensions")
    if os.path.isdir(default):
        return default
    return None


def _extension_dirs() -> List[str]:
    dirs = [BUILTIN_DIR]
    user = _user_extensions_dir()
    if user:
        dirs.append(user)
    return dirs


def _load_manifest(ext_dir: str, folder_name: str) -> Optional[Dict[str, Any]]:
    manifest_path = os.path.join(ext_dir, folder_name, "manifest.json")
    if not os.path.isfile(manifest_path):
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    ext_id = data.get("id") or folder_name
    if not ID_PATTERN.match(ext_id):
        return None
    entry = data.get("entry", "index.html")
    return {
        "id": ext_id,
        "name": data.get("name", ext_id),
        "tabLabel": data.get("tabLabel", data.get("name", ext_id)),
        "icon": data.get("icon", "extension"),
        "entry": entry,
        "entryUrl": f"/extensions/{ext_id}/{entry}",
        "description": data.get("description", ""),
    }


def list_extensions() -> List[Dict[str, Any]]:
    """Return all UI extensions from built-in and user directories."""
    seen_ids = set()
    result = []
    for base_dir in _extension_dirs():
        if not os.path.isdir(base_dir):
            continue
        for name in sorted(os.listdir(base_dir)):
            if name.startswith(".") or name.startswith("_"):
                continue
            path = os.path.join(base_dir, name)
            if not os.path.isdir(path):
                continue
            manifest = _load_manifest(base_dir, name)
            if not manifest or manifest["id"] in seen_ids:
                continue
            seen_ids.add(manifest["id"])
            result.append(manifest)
    return result


def get_extension_path(ext_id: str) -> Optional[str]:
    """Return the filesystem path of the extension folder, or None if not found."""
    if not ID_PATTERN.match(ext_id):
        return None
    for base_dir in _extension_dirs():
        # Check folder named exactly ext_id
        path = os.path.join(base_dir, ext_id)
        if os.path.isdir(path) and os.path.isfile(os.path.join(path, "manifest.json")):
            return path
        # Check folders whose manifest has id == ext_id
        for name in os.listdir(base_dir):
            if name.startswith(".") or name.startswith("_"):
                continue
            dir_path = os.path.join(base_dir, name)
            if not os.path.isdir(dir_path):
                continue
            manifest = _load_manifest(base_dir, name)
            if manifest and manifest["id"] == ext_id:
                return os.path.join(base_dir, name)
    return None
