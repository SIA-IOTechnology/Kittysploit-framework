#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SYSVOL helpers for targeted GPO file collection."""

from __future__ import annotations

import os
import re
import tempfile
from typing import Dict, List, Optional, Sequence, Tuple

from lib.protocols.smb.smb_client import SMBClient

GUID_RE = re.compile(r"\{[0-9A-Fa-f-]{36}\}", re.I)

GPO_FILE_PATTERNS: Dict[str, Tuple[str, ...]] = {
    "groups": (
        r"Machine\Preferences\Groups\Groups.xml",
        r"User\Preferences\Groups\Groups.xml",
        r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf",
    ),
    "registry": (
        r"Machine\Preferences\Registry\Registry.xml",
        r"User\Preferences\Registry\Registry.xml",
        r"Machine\Registry.pol",
        r"User\Registry.pol",
        r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf",
    ),
    "privilege": (
        r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf",
    ),
    "all": (),
}

GPO_FILE_PATTERNS["all"] = tuple(
    dict.fromkeys(
        GPO_FILE_PATTERNS["groups"]
        + GPO_FILE_PATTERNS["registry"]
        + GPO_FILE_PATTERNS["privilege"]
    )
)


def extract_gpo_guid(remote_path: str) -> str:
    match = GUID_RE.search(remote_path or "")
    return match.group(0).upper() if match else ""


def list_gpo_policy_files(
    client: SMBClient,
    domain: str,
    *,
    max_gpos: int = 50,
    category: str = "all",
) -> List[Tuple[str, str]]:
    """Return ``[(gpo_guid, remote_path), ...]`` for interesting GPO files."""
    suffixes = GPO_FILE_PATTERNS.get(category) or GPO_FILE_PATTERNS["all"]
    found: List[Tuple[str, str]] = []
    seen_guids: set[str] = set()
    base = f"\\{domain.strip().lower()}\\Policies"

    def _walk(path: str) -> None:
        if len(seen_guids) >= max_gpos and len(found) >= max_gpos * len(suffixes):
            return
        entries = client.list_path("SYSVOL", path)
        for entry in entries:
            name = entry.get("name") or ""
            if not name:
                continue
            child = f"{path.rstrip(chr(92))}\\{name}" if path != "\\" else f"\\{name}"
            if entry.get("is_dir"):
                guid = extract_gpo_guid(child)
                if guid:
                    seen_guids.add(guid)
                _walk(child)
                continue

            normalized = child.replace("/", "\\").lower()
            if any(normalized.endswith(suffix.lower()) for suffix in suffixes):
                found.append((extract_gpo_guid(child), child))

    _walk(base)
    return found[: max_gpos * len(suffixes)]


def _download_to_temp(client: SMBClient, remote_path: str, suffix: str) -> str:
    fd, local_path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    if not client.get_file("SYSVOL", remote_path, local_path):
        try:
            os.remove(local_path)
        except Exception:
            pass
        return ""
    return local_path


def download_gpo_text(client: SMBClient, remote_path: str) -> str:
    suffix = ".xml" if remote_path.lower().endswith(".xml") else ".inf"
    local_path = _download_to_temp(client, remote_path, suffix)
    if not local_path:
        return ""
    try:
        for encoding in ("utf-16", "utf-8"):
            try:
                with open(local_path, "r", encoding=encoding, errors="replace") as fp:
                    return fp.read()
            except Exception:
                continue
        with open(local_path, "rb") as fp:
            return fp.read().decode("utf-8", errors="replace")
    finally:
        try:
            os.remove(local_path)
        except Exception:
            pass


def download_gpo_bytes(client: SMBClient, remote_path: str) -> bytes:
    local_path = _download_to_temp(client, remote_path, ".pol")
    if not local_path:
        return b""
    try:
        with open(local_path, "rb") as fp:
            return fp.read()
    finally:
        try:
            os.remove(local_path)
        except Exception:
            pass


def parse_gpo_file(
    remote_path: str,
    content: str | bytes,
    *,
    modes: Optional[Sequence[str]] = None,
) -> Optional[Dict[str, object]]:
    from lib.protocols.gpo.parsers.groups_xml import parse_groups_xml
    from lib.protocols.gpo.parsers.gpttmpl import (
        parse_gpttmpl_group_membership,
        parse_gpttmpl_privilege_rights,
    )
    from lib.protocols.gpo.parsers.registry_pol import parse_registry_pol
    from lib.protocols.gpo.parsers.registry_xml import parse_registry_xml

    active = set(modes or ("groups", "registry", "privilege"))
    lowered = remote_path.lower()
    parsed: Dict[str, object] = {}

    if "groups" in active and lowered.endswith("groups.xml") and isinstance(content, str):
        result = parse_groups_xml(content)
        if result:
            parsed.update(result)

    if lowered.endswith("gpttmpl.inf") and isinstance(content, str):
        if "groups" in active:
            result = parse_gpttmpl_group_membership(content)
            if result:
                for key, value in result.items():
                    bucket = parsed.setdefault(key, {})
                    if isinstance(bucket, dict) and isinstance(value, dict):
                        bucket.update(value)
        if "privilege" in active:
            result = parse_gpttmpl_privilege_rights(content)
            if result:
                for key, value in result.items():
                    bucket = parsed.setdefault(key, {})
                    if isinstance(bucket, dict) and isinstance(value, dict):
                        bucket.update(value)

    if "registry" in active and lowered.endswith("registry.xml") and isinstance(content, str):
        result = parse_registry_xml(content)
        if result:
            parsed.update(result)

    if "registry" in active and lowered.endswith("registry.pol") and isinstance(content, (bytes, bytearray)):
        result = parse_registry_pol(bytes(content), policy_type_for_path(remote_path))
        if result:
            parsed.update(result)

    return parsed or None


def policy_type_for_path(remote_path: str) -> str:
    normalized = remote_path.replace("/", "\\").lower()
    if "\\user\\" in normalized:
        return "User"
    return "Machine"
