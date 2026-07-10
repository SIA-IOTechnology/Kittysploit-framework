#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parse JavaScript source maps and extract recoverable source intelligence."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

from lib.osint.js_secrets import extract_secret_hints

SOURCEMAP_URL_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)",
    re.IGNORECASE,
)
ENDPOINT_RX = re.compile(
    r"""(?:"|')((?:https?:\/\/[^\s"'<>]+)|(?:\/(?:api|v1|v2|graphql|rest|auth)[^"']*))(?:"|')""",
    re.IGNORECASE,
)
NOISE_SOURCE_SUFFIX = (
    ".png", ".jpg", ".svg", ".css", ".woff", ".woff2", ".ttf", ".map",
)


def resolve_sourcemap_url(js_body: str, js_url: str) -> Optional[str]:
    if not js_body:
        return None
    match = SOURCEMAP_URL_RE.search(js_body[-4096:])
    if not match:
        match = SOURCEMAP_URL_RE.search(js_body)
    if not match:
        return None
    ref = match.group(1).strip().strip('"').strip("'")
    if ref.startswith("data:"):
        return ref
    return urljoin(js_url, ref)


def decode_data_sourcemap(data_url: str) -> Optional[Dict[str, Any]]:
    if not data_url.startswith("data:"):
        return None
    try:
        header, payload = data_url.split(",", 1)
        if ";base64" in header:
            raw = base64.b64decode(payload)
        else:
            raw = payload.encode("utf-8", errors="replace")
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


def parse_sourcemap_json(raw: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def extract_from_sourcemap(
    smap: Dict[str, Any],
    *,
    js_url: str = "",
    max_sources: int = 512,
) -> Dict[str, Any]:
    sources = [str(s) for s in (smap.get("sources") or []) if s]
    contents = smap.get("sourcesContent") or []
    endpoints: Set[str] = set()
    keys: List[Dict[str, str]] = []
    recovered: List[Dict[str, Any]] = []

    for idx, source_path in enumerate(sources):
        if idx >= max_sources:
            break
        if any(str(source_path).lower().endswith(ext) for ext in NOISE_SOURCE_SUFFIX):
            continue
        body = ""
        if isinstance(contents, list) and idx < len(contents):
            body = str(contents[idx] or "")
        entry: Dict[str, Any] = {
            "source": str(source_path)[:512],
            "has_content": bool(body),
            "size": len(body),
        }
        if body:
            for endpoint in ENDPOINT_RX.findall(body):
                endpoints.add(endpoint[:512])
            keys.extend(extract_secret_hints(body, source_path))
        recovered.append(entry)

    # Dedupe secrets across files
    deduped: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in keys:
        key = (str(row.get("name", "")).lower(), str(row.get("value", "")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)

    return {
        "js_url": js_url,
        "source_count": len(sources),
        "recovered_sources": recovered,
        "endpoints": sorted(endpoints)[:200],
        "key_hints": deduped[:80],
        "file": smap.get("file"),
        "version": smap.get("version"),
    }


def analyze_js_bundle(js_url: str, js_body: str, map_body: str = "") -> Optional[Dict[str, Any]]:
    map_url = resolve_sourcemap_url(js_body, js_url)
    smap: Optional[Dict[str, Any]] = None
    if map_body:
        smap = parse_sourcemap_json(map_body)
    elif map_url:
        if map_url.startswith("data:"):
            smap = decode_data_sourcemap(map_url)
        else:
            return {
                "js_url": js_url,
                "map_url": map_url,
                "needs_fetch": True,
            }
    if not smap:
        return None
    out = extract_from_sourcemap(smap, js_url=js_url)
    out["map_url"] = map_url
    return out
