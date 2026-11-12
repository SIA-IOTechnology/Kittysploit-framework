#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
When the HTTP stack fingerprint confirms WordPress, merge the full WordPress
module family from the HTTP catalog into the active scan set.

Non-WordPress targets keep the low-noise default surface; WordPress targets
run every ``scanner/http`` module that targets WordPress / wp-* / plugins.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Set

# Same token set as ``filter_vendor_detect_on_confirmed_cms`` (stack_fingerprint).
_WP_PATH_TOKENS = (
    "wordpress",
    "wp_plugin",
    "wp_",
    "xmlrpc",
    "woocommerce",
)


def _tags(module: Mapping[str, Any]) -> Set[str]:
    return {str(t).lower() for t in (module.get("tags") or [])}


def is_wordpress_scan_module(module: Mapping[str, Any]) -> bool:
    """True if this HTTP scanner module is WordPress-specific."""
    path = str(module.get("path") or "").lower()
    if not path.startswith("scanner/http/"):
        return False
    tags = _tags(module)
    if tags & {"wordpress", "wp", "wp-plugin", "wp-theme", "wpscan"}:
        return True
    if path.startswith("scanner/http/wp_"):
        return True
    if any(tok in path for tok in _WP_PATH_TOKENS):
        return True
    return False


def wordpress_modules_from_catalog(
    http_catalog: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for row in http_catalog:
        if is_wordpress_scan_module(row):
            rows.append(dict(row))
    rows.sort(key=lambda m: str(m.get("path") or ""))
    return rows


def augment_wordpress_scan_modules(
    current: Sequence[Dict[str, Any]],
    http_catalog: Sequence[Dict[str, Any]],
    options: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """After WordPress is confirmed, add every WordPress module from the catalog."""
    if options.get("module"):
        return list(current)
    if options.get("tags") and "wordpress" not in {
        str(t).lower() for t in (options.get("tags") or [])
    }:
        return list(current)

    by_path: Dict[str, Dict[str, Any]] = {
        str(m.get("path") or ""): dict(m) for m in current if m.get("path")
    }
    wp_rows = wordpress_modules_from_catalog(http_catalog)
    for row in wp_rows:
        path = str(row.get("path") or "")
        if path:
            by_path.setdefault(path, row)
    return list(by_path.values())


# Back-compat alias for tests
is_wordpress_plugin_cve_module = is_wordpress_scan_module

__all__ = [
    "augment_wordpress_scan_modules",
    "is_wordpress_scan_module",
    "is_wordpress_plugin_cve_module",
    "wordpress_modules_from_catalog",
]
