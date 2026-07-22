#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Install marketplace extensions from public GitHub repositories."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple
import requests

# Built-in mapping when the registry catalog has no bundle (e.g. no GitHub Releases).
DEFAULT_GITHUB_SOURCES: Dict[str, Dict[str, str]] = {
    "kittyproxy": {
        "repo": "SIA-IOTechnology/KittyProxy",
        "ref": "main",
    },
    "kittyosint": {
        "repo": "SIA-IOTechnology/KittyOsint",
        "ref": "main",
    },
    "kittyprotocol": {
        "repo": "SIA-IOTechnology/KittyProtocol",
        "ref": "main",
    },
    "kittycluster": {
        "repo": "SIA-IOTechnology/KittyCluster",
        "ref": "main",
    },
    "kittycosmic": {
        "repo": "SIA-IOTechnology/KittyCosmic",
        "ref": "main",
    },
    "kittyv8": {
        "repo": "SIA-IOTechnology/KittyV8Debugger",
        "ref": "main",
    },
}

_GITHUB_SPEC_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$",
    re.IGNORECASE,
)
_GITHUB_SHORT_RE = re.compile(r"^github:([^/]+)/([^/@#]+)(?:@(.+))?$", re.IGNORECASE)


def _load_config_sources() -> Dict[str, Dict[str, str]]:
    sources = {k: dict(v) for k, v in DEFAULT_GITHUB_SOURCES.items()}
    try:
        import toml

        config_path = os.path.join("config", "kittysploit.toml")
        if not os.path.isfile(config_path):
            return sources
        with open(config_path, "r", encoding="utf-8") as handle:
            config = toml.load(handle) or {}
        marketplace = config.get("marketplace") or {}
        configured = marketplace.get("sources") or {}
        for ext_id, entry in configured.items():
            if not isinstance(entry, dict):
                continue
            if (entry.get("type") or "").lower() != "github":
                continue
            repo = entry.get("repo") or entry.get("repository")
            if not repo:
                continue
            sources[str(ext_id)] = {
                "repo": str(repo).strip().strip("/"),
                "ref": str(entry.get("ref") or entry.get("branch") or "main").strip(),
            }
    except Exception:
        pass
    return sources


def get_github_source(extension_id: str) -> Optional[Tuple[str, str]]:
    """Return (owner/repo, ref) for a marketplace extension id, if configured."""
    sources = _load_config_sources()
    entry = sources.get(extension_id)
    if not entry:
        return None
    repo = entry.get("repo", "").strip()
    if not repo:
        return None
    return repo, entry.get("ref") or "main"


def parse_github_spec(value: str) -> Optional[Tuple[str, str]]:
    """
    Parse github:owner/repo@ref, owner/repo, or https://github.com/owner/repo URLs.
    """
    value = (value or "").strip()
    if not value:
        return None

    short = _GITHUB_SHORT_RE.match(value)
    if short:
        owner, repo, ref = short.group(1), short.group(2), short.group(3)
        return f"{owner}/{repo}", (ref or "main").strip()

    if value.startswith(("http://", "https://")) or "github.com" in value:
        match = _GITHUB_SPEC_RE.match(value)
        if match:
            return f"{match.group(1)}/{match.group(2)}", "main"

    if "/" in value and " " not in value and not value.startswith("."):
        parts = value.split("@", 1)
        repo = parts[0].strip().strip("/")
        ref = parts[1].strip() if len(parts) > 1 else "main"
        if repo.count("/") == 1 and not repo.startswith("/"):
            return repo, ref or "main"

    return None


def _github_archive_urls(repo: str, ref: str) -> Tuple[str, ...]:
    repo = repo.strip().strip("/")
    ref = ref.strip()
    return (
        f"https://github.com/{repo}/archive/refs/heads/{ref}.zip",
        f"https://github.com/{repo}/archive/refs/tags/{ref}.zip",
    )


def find_extension_root(extract_dir: Path) -> Optional[Path]:
    """Locate the folder that contains extension.toml inside an extracted archive."""
    if (extract_dir / "extension.toml").is_file():
        return extract_dir
    for child in extract_dir.iterdir():
        if child.is_dir() and (child / "extension.toml").is_file():
            return child
    for child in extract_dir.iterdir():
        if not child.is_dir():
            continue
        for nested in child.iterdir():
            if nested.is_dir() and (nested / "extension.toml").is_file():
                return nested
    return None


def extract_extension_bundle(bundle_path: str) -> Path:
    """
    Extract a local .zip or .kext marketplace bundle.

    Returns a temp directory containing extension files (with extension.toml at root).
    Caller must delete the returned directory with shutil.rmtree().
    """
    bundle = Path(bundle_path).resolve()
    if not bundle.is_file():
        raise FileNotFoundError(f"Bundle not found: {bundle}")

    if bundle.suffix.lower() not in (".zip", ".kext"):
        raise ValueError(f"Expected a .zip or .kext file, got: {bundle.name}")

    work_dir = Path(tempfile.mkdtemp(prefix="kittysploit_bundle_"))
    extract_dir = work_dir / "extract"
    extract_dir.mkdir()
    try:
        with zipfile.ZipFile(bundle, "r") as archive:
            archive.extractall(extract_dir)

        extension_root = find_extension_root(extract_dir)
        if extension_root is None:
            raise FileNotFoundError(f"No extension.toml found inside {bundle.name}")

        staging = work_dir / "extension"
        shutil.copytree(extension_root, staging)
        return staging
    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    finally:
        extract_sub = work_dir / "extract"
        if extract_sub.exists():
            shutil.rmtree(extract_sub, ignore_errors=True)


def download_github_extension(repo: str, ref: str, timeout: int = 120) -> Path:
    """
    Download a public GitHub repo archive and return a temp directory with extension files.

    Caller must delete the returned directory when done (shutil.rmtree).
    """
    last_error: Optional[Exception] = None
    response = None
    for url in _github_archive_urls(repo, ref):
        try:
            response = requests.get(url, timeout=timeout, stream=True)
            if response.status_code == 404:
                continue
            response.raise_for_status()
            break
        except Exception as exc:
            last_error = exc
            response = None
    else:
        if last_error:
            raise last_error
        raise FileNotFoundError(
            f"GitHub archive not found for {repo} (ref={ref}). "
            "Check the repository is public and the branch/tag exists."
        )

    work_dir = Path(tempfile.mkdtemp(prefix="kittysploit_github_"))
    zip_path = work_dir / "archive.zip"
    try:
        with open(zip_path, "wb") as handle:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    handle.write(chunk)

        extract_dir = work_dir / "extract"
        extract_dir.mkdir()
        with zipfile.ZipFile(zip_path, "r") as archive:
            archive.extractall(extract_dir)

        extension_root = find_extension_root(extract_dir)
        if extension_root is None:
            raise FileNotFoundError(
                f"No extension.toml found in GitHub archive for {repo}@{ref}"
            )

        staging = work_dir / "extension"
        shutil.copytree(extension_root, staging)
        return staging
    finally:
        zip_path.unlink(missing_ok=True)
        extract_sub = work_dir / "extract"
        if extract_sub.exists():
            shutil.rmtree(extract_sub, ignore_errors=True)
