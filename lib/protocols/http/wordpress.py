#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.framework.base_module import BaseModule

import re


class Wordpress(BaseModule):
    """WordPress HTTP helper methods for exploit/scanner modules."""

    @staticmethod
    def wp_normalize_base_path(path_value: str) -> str:
        value = (path_value or "/").strip()
        if value == "/":
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        return "/" + value.strip("/")

    @staticmethod
    def wp_plugin_path(base_path: str, plugin_slug: str, *parts: str) -> str:
        root = Wordpress.wp_normalize_base_path(base_path)
        slug = (plugin_slug or "").strip("/")
        clean_parts = [part.strip("/") for part in parts if part and part.strip("/")]
        plugin_root = f"{root}/wp-content/plugins/{slug}"
        if clean_parts:
            return plugin_root + "/" + "/".join(clean_parts)
        return plugin_root

    @staticmethod
    def wp_extract_version_from_readme(readme_text: str):
        patterns = (
            r"^Stable tag:\s*([0-9][0-9A-Za-z\.\-_]*)",
            r"^Version:\s*([0-9][0-9A-Za-z\.\-_]*)",
        )
        for pattern in patterns:
            match = re.search(pattern, readme_text or "", flags=re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1).strip()
        return None

    @staticmethod
    def wp_version_to_tuple(version: str):
        return tuple(int(part) for part in re.findall(r"\d+", version or ""))

    @staticmethod
    def wp_version_in_range(version: str, low: tuple, high: tuple) -> bool:
        """Return True when *version* is within [*low*, *high*] (inclusive, numeric tuple compare)."""
        current = Wordpress.wp_version_to_tuple(version)
        low_p = tuple(low) + (0,) * max(0, 3 - len(low))
        high_p = tuple(high) + (0,) * max(0, 3 - len(high))
        while len(current) < 3:
            current = current + (0,)
        return low_p[:3] <= current[:3] <= high_p[:3]

    def wp_json_index_path(self, base_path: str = None) -> str:
        root = Wordpress.wp_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        return f"{root}/wp-json/" if root != "/" else "/wp-json/"

    def wp_rest_has_namespace(self, namespace: str, base_path: str = None) -> bool:
        """True when ``/wp-json/`` lists the given REST namespace."""
        import json

        response = self.http_request(
            method="GET",
            path=self.wp_json_index_path(base_path),
            allow_redirects=True,
            timeout=float(getattr(self, "timeout", None) or 15),
        )
        if not response or response.status_code != 200:
            return False
        try:
            payload = response.json()
        except Exception:
            try:
                payload = json.loads(response.text or "")
            except Exception:
                return False
        namespaces = payload.get("namespaces") or []
        return namespace in namespaces

    def wp_plugin_version(self, plugin_slug: str, base_path: str = None) -> str:
        """Read plugin version from readme.txt (Stable tag / Version)."""
        path = self.wp_plugin_path(
            base_path if base_path is not None else getattr(self, "path", "/"),
            plugin_slug,
            "readme.txt",
        )
        response = self.http_request(
            method="GET",
            path=path,
            allow_redirects=True,
            timeout=float(getattr(self, "timeout", None) or 15),
        )
        if not response or response.status_code != 200:
            return ""
        return self.wp_extract_version_from_readme(response.text or "") or ""

    # Backward-compatible aliases
    normalize_base_path = wp_normalize_base_path
    plugin_path = wp_plugin_path
    extract_version_from_readme = wp_extract_version_from_readme
    version_to_tuple = wp_version_to_tuple
