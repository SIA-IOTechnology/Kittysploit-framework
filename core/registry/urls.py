#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Canonical marketplace / registry server URL."""

from typing import Optional

DEFAULT_REGISTRY_URL = "https://report.kittysploit.com"
DEFAULT_REPORTS_URL = DEFAULT_REGISTRY_URL

_LEGACY_REGISTRY_URLS = frozenset({
    "https://app.kittysploit.com",
    "http://app.kittysploit.com",
    "https://registry.kittysploit.com",
    "http://registry.kittysploit.com",
})


def normalize_registry_url(url: Optional[str]) -> str:
    """Return a usable registry URL, rewriting retired KittySploit hosts."""
    cleaned = str(url or "").strip().rstrip("/")
    if not cleaned:
        return DEFAULT_REGISTRY_URL
    if cleaned.lower() in _LEGACY_REGISTRY_URLS:
        return DEFAULT_REGISTRY_URL
    return cleaned
