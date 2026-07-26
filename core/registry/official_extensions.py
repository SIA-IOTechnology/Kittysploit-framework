#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Official marketplace extensions distributed via GitHub."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.registry.github_install import _load_config_sources

_MANIFEST_FETCH_TIMEOUT = 8


def _framework_root() -> Optional[Path]:
    try:
        from core.utils.marketplace_apps import framework_root

        return framework_root()
    except Exception:
        return None


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


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

        data = toml.load(manifest_path) or {}
        return {
            "id": data.get("id"),
            "name": data.get("name"),
            "version": data.get("version"),
            "description": data.get("description", ""),
            "author": data.get("author", "KittySploit Team"),
            "extension_type": data.get("extension_type", "UI"),
            "price": data.get("metadata", {}).get("price", 0) if isinstance(data.get("metadata"), dict) else 0,
        }
    except Exception:
        return {}


def _fetch_github_manifest(repo: str, ref: str) -> Dict[str, Any]:
    try:
        import requests

        url = f"https://raw.githubusercontent.com/{repo.strip('/')}/{ref}/extension.toml"
        response = requests.get(url, timeout=_MANIFEST_FETCH_TIMEOUT)
        if response.status_code != 200:
            return {}

        try:
            import tomllib

            data = tomllib.loads(response.text) or {}
        except ImportError:
            import toml

            data = toml.loads(response.text) or {}

        return {
            "id": data.get("id"),
            "name": data.get("name"),
            "version": data.get("version"),
            "description": data.get("description", ""),
            "author": data.get("author", "KittySploit Team"),
            "extension_type": data.get("extension_type", "UI"),
        }
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
        "install_hint": ext_id,
    }


def _resolve_manifest(ext_id: str, github: Dict[str, str], root: Optional[Path]) -> Dict[str, Any]:
    manifest: Dict[str, Any] = {}
    if root is not None:
        app_dir = root / "apps" / ext_id
        if app_dir.is_dir():
            manifest = _read_manifest_toml(app_dir)

    if not manifest.get("name"):
        repo = github.get("repo", "")
        ref = github.get("ref", "main")
        if repo:
            manifest = _fetch_github_manifest(repo, ref) or manifest

    if not manifest.get("id"):
        manifest["id"] = ext_id
    return manifest


def get_official_marketplace_modules() -> List[Dict[str, Any]]:
    sources = _load_config_sources()
    root = _framework_root()
    modules: List[Dict[str, Any]] = []

    for ext_id, github in sources.items():
        manifest = _resolve_manifest(ext_id, github, root)
        modules.append(_build_official_module(ext_id, github, manifest))

    return modules


def _annotate_remote_with_official(
    remote: Dict[str, Any],
    official: Dict[str, Any],
) -> Dict[str, Any]:
    enriched = dict(remote)
    enriched["source"] = "github_official"
    enriched["github_repo"] = official.get("github_repo", "")
    enriched["github_ref"] = official.get("github_ref", "main")
    enriched["repository"] = official.get("repository", "")
    enriched["install_hint"] = official.get("id", "")
    enriched["can_download"] = True
    enriched["is_free"] = True
    if official.get("version"):
        enriched["version"] = official.get("version")
    return enriched


def merge_official_modules(
    remote_modules: List[Dict[str, Any]],
    *,
    search_query: Optional[str] = None,
    category: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Merge official GitHub extensions into marketplace browse results.

    Catalog entries with the same name as an official app are annotated with
    GitHub source (no duplicate row). Unmatched official apps are appended.
    """
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

    official_by_id = {str(m.get("id", "")).lower(): m for m in official if m.get("id")}
    official_by_name = {_normalize_name(str(m.get("name", ""))): m for m in official if m.get("name")}

    existing_ids: set[str] = set()
    matched_official_ids: set[str] = set()
    merged: List[Dict[str, Any]] = []

    for remote in remote_modules:
        for key in ("id", "slug", "extension_id", "manifest_id", "code", "package_id"):
            value = remote.get(key)
            if value is not None:
                existing_ids.add(str(value).strip().lower())

        norm_name = _normalize_name(str(remote.get("name", "")))
        official_match = official_by_name.get(norm_name)
        if official_match is not None:
            matched_official_ids.add(str(official_match.get("id", "")).lower())
            merged.append(_annotate_remote_with_official(remote, official_match))
        else:
            merged.append(remote)

    for module in official:
        ext_id = str(module.get("id", "")).strip().lower()
        if not ext_id or ext_id in existing_ids or ext_id in matched_official_ids:
            continue
        merged.append(module)
        existing_ids.add(ext_id)

    return merged
