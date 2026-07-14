#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize crawler / recon output into injection scan targets."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlparse


def _dedupe_preserve(items: Iterable[str], *, limit: int = 200) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for raw in items:
        value = str(raw or "").strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def parse_csv_option(value: Any) -> List[str]:
    """Parse a module option that may be a CSV string or a list."""
    if value is None:
        return []
    if hasattr(value, "value"):
        value = value.value
    if isinstance(value, (list, tuple, set)):
        return _dedupe_preserve(str(item).strip() for item in value)
    text = str(value).strip()
    if not text:
        return []
    return _dedupe_preserve(part.strip() for part in text.split(",") if part.strip())


def summarize_crawl_urls(
    urls: Sequence[str],
    *,
    target_host: str = "",
) -> Dict[str, List[str]]:
    """Turn absolute crawled URLs into paths and query parameter names."""
    host = (target_host or "").strip().lower().split(":", 1)[0]
    paths: List[str] = []
    params: List[str] = []
    normalized_urls: List[str] = []

    for raw in urls or []:
        text = str(raw or "").strip()
        if not text:
            continue
        parsed = urlparse(text)
        if parsed.scheme not in ("http", "https"):
            continue
        if host and parsed.hostname and parsed.hostname.lower() not in {host, f"www.{host}"}:
            if not parsed.hostname.lower().endswith(f".{host}"):
                continue
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        paths.append(path)
        normalized_urls.append(text)
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            if key:
                params.append(key)

    return {
        "urls": _dedupe_preserve(normalized_urls, limit=300),
        "paths": _dedupe_preserve(paths, limit=120),
        "params": _dedupe_preserve(params, limit=80),
    }


def merge_scan_paths(*groups: Iterable[str], limit: int = 120) -> List[str]:
    return _dedupe_preserve(
        (item for group in groups for item in (group or [])),
        limit=limit,
    )


def merge_param_names(
    *groups: Iterable[str],
    fallback: Iterable[str] = (),
    limit: int = 40,
) -> List[str]:
    merged = _dedupe_preserve((item for group in groups for item in (group or [])), limit=limit)
    if merged:
        return merged
    return _dedupe_preserve(fallback, limit=limit)


def build_injection_targets(
    paths: Sequence[str],
    params: Sequence[str],
) -> List[Tuple[str, str]]:
    targets: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for raw_path in paths or []:
        path = str(raw_path or "").strip()
        if not path:
            continue
        if not path.startswith("/"):
            parsed = urlparse(path)
            if parsed.scheme in ("http", "https"):
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
            else:
                path = f"/{path.lstrip('/')}"
        parsed = urlparse(path)
        base_path = parsed.path or "/"
        query_params = [key for key, _value in parse_qsl(parsed.query, keep_blank_values=True) if key]
        candidate_params = _dedupe_preserve(list(query_params) + list(params or []), limit=24)
        if not candidate_params:
            continue
        for param in candidate_params:
            key = (base_path, param.lower())
            if key in seen:
                continue
            seen.add(key)
            targets.append((base_path, param))
    return targets[:80]
