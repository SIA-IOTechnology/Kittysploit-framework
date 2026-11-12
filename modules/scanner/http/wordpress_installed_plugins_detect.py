#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate installed WordPress plugins (readme.txt + REST namespaces)."""

from __future__ import annotations

import json
import re
from typing import Dict, List, Set

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


# High-traffic plugin slugs — readme probe is cheap (404 vs 200).
_COMMON_PLUGIN_SLUGS: tuple[str, ...] = (
    "elementor",
    "elementor-pro",
    "woocommerce",
    "wordpress-seo",
    "contact-form-7",
    "jetpack",
    "wordfence",
    "wpforms-lite",
    "all-in-one-seo-pack",
    "google-site-kit",
    "classic-editor",
    "akismet",
    "duplicate-post",
    "wp-super-cache",
    "w3-total-cache",
    "litespeed-cache",
    "updraftplus",
    "really-simple-ssl",
    "redirection",
    "kirki",
    "advanced-custom-fields",
    "acf",
    "mailchimp-for-wp",
    "wp-mail-smtp",
    "ultimate-member",
    "memberpress",
    "learndash",
    "gravityforms",
    "ninja-forms",
    "revslider",
    "js_composer",
    "wpml",
    "polylang",
    "bbpress",
    "buddypress",
    "woocommerce-payments",
    "woocommerce-gateway-stripe",
)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Installed Plugins Inventory",
        "description": (
            "Probes readme.txt for common plugin slugs and parses /wp-json/ "
            "for plugin-specific REST namespaces."
        ),
        "author": ["KittySploit Team"],
        "severity": "low",
        "tags": ["web", "scanner", "wordpress", "listing", "plugin", "inventory"],
    }

    def _namespaces_from_index(self) -> Set[str]:
        response = self.http_request(
            method="GET", path="/wp-json/", allow_redirects=True
        )
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            return set()
        try:
            payload = json.loads(response.text or "")
        except json.JSONDecodeError:
            return set()
        if not isinstance(payload, dict):
            return set()
        namespaces = payload.get("namespaces") or []
        return {str(ns) for ns in namespaces if ns and str(ns) != "wp/v2"}

    def _slugs_from_plugins_dir_listing(self) -> Set[str]:
        response = self.http_request(
            method="GET",
            path="/wp-content/plugins/",
            allow_redirects=False,
        )
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            return set()
        text = response.text or ""
        if "index of" not in text.lower():
            return set()
        return set(re.findall(r"/wp-content/plugins/([a-z0-9._-]+)/", text, re.I))

    def run(self):
        found: Dict[str, str] = {}

        for slug in _COMMON_PLUGIN_SLUGS:
            version = self.wp_plugin_version(slug, "/")
            if version:
                found[slug] = version
                continue
            readme_path = self.wp_plugin_path("/", slug, "readme.txt")
            response = self.http_request(
                method="GET", path=readme_path, allow_redirects=True
            )
            if response and int(getattr(response, "status_code", 0) or 0) == 200:
                ver = self.wp_extract_version_from_readme(response.text or "")
                found[slug] = ver or "present"

        for slug in self._slugs_from_plugins_dir_listing():
            if slug not in found:
                found[slug] = found.get(slug) or "present (dir listing)"

        namespaces = self._namespaces_from_index()
        if namespaces:
            ns_line = ", ".join(sorted(namespaces)[:25])
            if len(namespaces) > 25:
                ns_line += f" (+{len(namespaces) - 25})"
        else:
            ns_line = ""

        if not found and not namespaces:
            return False

        parts: List[str] = []
        if found:
            for slug in sorted(found.keys()):
                ver = found[slug]
                parts.append(f"{slug}@{ver}" if ver != "present" else slug)
        detail = "; ".join(parts[:40])
        if len(parts) > 40:
            detail += f" (+{len(parts) - 40} more)"
        if ns_line:
            detail = (detail + " | REST namespaces: " + ns_line).strip(" |")

        self.set_info(
            severity="low",
            reason="WordPress plugins / REST surface inventory",
            detail=detail,
            paths=["/wp-content/plugins/", "/wp-json/"],
        )
        return True
