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

    # Backward-compatible aliases
    normalize_base_path = wp_normalize_base_path
    plugin_path = wp_plugin_path
    extract_version_from_readme = wp_extract_version_from_readme
    version_to_tuple = wp_version_to_tuple
