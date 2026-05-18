#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Official marketplace extensions distributed via GitHub (bundled in apps/)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.registry.github_install import _load_config_sources


def _framework_root() -> Optional[Path]:
    try:
        from core.utils.marketplace_apps import framework_root

        return framework_root()
    except Exception:
        return None


def _read_manifest_toml(app_dir: Path) -> Dict[str, Any]:
    manifest_path = app_dir / "extension.toml"
    if not manifest_path.is_file():
        return {}

    try:
        from core.registry.manifest import ManifestParser

        manifest = ManifestParser.parse(str(manifest_path))
        if not manifest:
            return {}
        ext_type = manifest.extension_type.value if hasattr(manifest.extension_type, "value") else str(manifest.extension_type)
        return {
            "id": manifest.id,
            "name": manifest.name,
            "version": manifest.version,
            "description": manifest.description or "",
            "author": manifest.author or "KittySploit Team",
            "extension_type": ext_type,
            "price": manifest.price,
        }
    except Exception:
        pass

    try:
        import toml

        return toml.load(manifest_path) or {}
    except Exception:
        return {}


def _extension_type_label(raw: str) -> str:
    value = (raw or "").strip().lower()
    if value in ("ui", "interface"):
        return "interface"
    return value or "interface"


def _build_official_module(ext_id: str, github: Dict[str, str], manifest: Dict[str, Any]) -> Dict[str, Any]:
    repo = github.get("repo", "")
    ref = github.get("ref", "main")
    name = manifest.get("name") or ext_id
    version = manifest.get("version") or "0.0.0"
    description = manifest.get("description") or f"Official KittySploit extension (GitHub: {repo})"
    author = manifest.get("author") or "KittySploit Team"
    if isinstance(author, dict):
        author_name = author.get("username") or author.get("name") or "KittySploit Team"
    else:
        author_name = str(author)

    return {
        "id": ext_id,
        "slug": ext_id,
        "name": name,
        "description": description,
        "author": {"username": author_name},
        "type": _extension_type_label(manifest.get("extension_type", "UI")),
        "price": 0,
        "is_free": True,
        "can_download": True,
        "has_purchased": False,
        "is_author": False,
        "downloads": 0,
        "rating": 0,
        "rating_count": 0,
        "version": version,
        "source": "github_official",
        "github_repo": repo,
        "github_ref": ref,
        "repository": f"https://github.com/{repo}" if repo else "",
    }


def get_official_marketplace_modules() -> List[Dict[str, Any]]:
    """Build browse/search entries for official GitHub-hosted extensions."""
    sources = _load_config_sources()
    root = _framework_root()
    modules: List[Dict[str, Any]] = []

    for ext_id, github in sources.items():
        manifest: Dict[str, Any] = {}
        if root is not None:
            app_dir = root / "apps" / ext_id
            if app_dir.is_dir():
                manifest = _read_manifest_toml(app_dir)
        if not manifest.get("id"):
            manifest["id"] = ext_id
        modules.append(_build_official_module(ext_id, github, manifest))

    return modules


def merge_official_modules(
    remote_modules: List[Dict[str, Any]],
    *,
    search_query: Optional[str] = None,
    category: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Append official GitHub extensions not already listed in the remote catalog."""
    official = get_official_marketplace_modules()

    if search_query:
        query = search_query.strip().lower()
        official = [
            module
            for module in official
            if query in str(module.get("id", "")).lower()
            or query in str(module.get("name", "")).lower()
            or query in str(module.get("description", "")).lower()
            or query in str(module.get("github_repo", "")).lower()
        ]

    if category:
        cat = category.strip().lower()
        official = [m for m in official if str(m.get("type", "")).lower() == cat]

    existing_ids: set[str] = set()
    for module in remote_modules:
        for key in ("id", "slug", "extension_id", "manifest_id", "code", "package_id"):
            value = module.get(key)
            if value is not None:
                existing_ids.add(str(value).strip().lower())

    merged = list(remote_modules)
    for module in official:
        ext_id = str(module.get("id", "")).strip().lower()
        if not ext_id or ext_id in existing_ids:
            continue
        merged.append(module)
        existing_ids.add(ext_id)

    return merged
