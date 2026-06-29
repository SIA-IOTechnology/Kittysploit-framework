#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Handle extraction and generic-identity filtering for OSINT profile discovery."""

from __future__ import annotations

import re
from typing import Dict, List, Pattern, Set
from urllib.parse import urlparse, urlunparse

# Mailbox local-parts and usernames too common to infer a real person/org profile.
GENERIC_LOCAL_PARTS: Set[str] = {
    "info", "contact", "admin", "administrator", "support", "sales", "hr",
    "help", "helpdesk", "mail", "email", "webmaster", "postmaster", "abuse",
    "noreply", "no-reply", "donotreply", "newsletter", "marketing", "office",
    "enquiry", "inquiry", "hello", "team", "service", "customerservice",
    "billing", "accounts", "jobs", "career", "careers", "press", "media",
    "security", "privacy", "legal", "compliance", "feedback", "notify",
    "notification", "alerts", "system", "root", "user", "test", "demo",
    "guest", "public", "general", "reception", "shop", "store", "orders",
    "welcome", "register", "signup", "subscribe", "news", "updates",
}

# Per-platform username syntax (only API-backed platforms are probed).
PLATFORM_HANDLE_RULES: Dict[str, Pattern[str]] = {
    # GitHub: alphanumeric or hyphen, no dots, 1-39 chars.
    "github": re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$"),
    # GitLab: letters, digits, underscore, hyphen, dot — no spaces.
    "gitlab": re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$"),
    # Reddit: letters, digits, underscore, hyphen only — 3-20 chars.
    "reddit": re.compile(r"^[A-Za-z0-9_-]{3,20}$"),
    # dev.to: letters, digits, underscore, hyphen.
    "devto": re.compile(r"^[a-zA-Z0-9_-]{1,30}$"),
}

API_VERIFIED_PLATFORMS: Set[str] = set(PLATFORM_HANDLE_RULES.keys())


def is_valid_handle_for_platform(handle: str, platform: str) -> bool:
    """Return False when a handle cannot exist on the target platform."""
    token = str(handle or "").strip()
    if not token or is_generic_handle(token):
        return False
    pattern = PLATFORM_HANDLE_RULES.get(str(platform or "").strip().lower())
    if not pattern:
        return False
    return bool(pattern.match(token))


def normalize_profile_url(url: str) -> str:
    """Strip default ports (e.g. :443) from profile URLs for clean output."""
    if not url:
        return url
    try:
        parsed = urlparse(url)
        port = parsed.port
        if (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80):
            netloc = parsed.hostname or ""
        else:
            netloc = parsed.netloc
        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    except Exception:
        return url


def is_generic_handle(handle: str) -> bool:
    """Return True when a handle is too generic for reliable profile attribution."""
    token = str(handle or "").strip().lower()
    if not token:
        return True
    if token in GENERIC_LOCAL_PARTS:
        return True
    if token.isdigit():
        return True
    if len(token) < 4:
        return True
    return False


def extract_handles(query: str, query_type: str) -> List[str]:
    """Derive non-generic handle candidates from a username, email, or full name."""
    handles: Set[str] = set()
    q = str(query or "").strip()
    qtype = str(query_type or "username").strip().lower()

    if not q:
        return []

    if qtype == "email" and "@" in q:
        local = q.split("@", 1)[0].strip().lower()
        if local and not is_generic_handle(local):
            handles.add(local)
        for variant in re.split(r"[._\-+]", local):
            variant = variant.strip().lower()
            if variant and not is_generic_handle(variant):
                handles.add(variant)
    elif qtype == "name":
        base = re.sub(r"[^a-zA-Z0-9 ]", " ", q)
        parts = [p.lower() for p in base.split() if len(p) >= 2]
        if parts:
            candidates = [
                "".join(parts),
                ".".join(parts),
                "_".join(parts),
            ]
            if len(parts) >= 2:
                candidates.append(parts[0] + parts[-1])
                candidates.append(parts[0][0] + parts[-1] if parts[0] else parts[-1])
            for candidate in candidates:
                if candidate and not is_generic_handle(candidate):
                    handles.add(candidate)
    else:
        cleaned = re.sub(r"[^a-zA-Z0-9._\-]", "", q).lower()
        if cleaned and not is_generic_handle(cleaned):
            handles.add(cleaned)

    return sorted(handles)
