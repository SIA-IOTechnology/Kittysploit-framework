#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared React / Vite / CRA fingerprinting and exposure helpers."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from lib.scanner.http.detectors import (
    classify_spa_stack,
    evidence_react,
    is_nextjs,
    is_react,
)

_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']""",
    re.I,
)
_SOURCEMAP_RE = re.compile(
    r"""[#@]\s*sourceMappingURL\s*=\s*(\S+)""",
    re.I,
)
_ENV_KEY_RE = re.compile(
    r"""\b((?:REACT_APP_|VITE_|NEXT_PUBLIC_)[A-Z0-9_]+)\s*[:=]\s*["']?([^"'\s,;}]{3,})""",
    re.I,
)
_DOTENV_LINE_RE = re.compile(
    r"""^(?:export\s+)?([A-Z][A-Z0-9_]*)=(.+)$""",
    re.M,
)


def probe_react_stack(module: Any) -> Tuple[bool, str, str]:
    """
    GET homepage and classify SPA stack.

    Returns:
        (ok, reason, stack) where stack is classify_spa_stack() value.
    """
    try:
        response = module.http_request(method="GET", path="/", allow_redirects=True)
    except Exception as exc:
        return False, f"baseline unreachable: {exc}", "none"
    if not response:
        return False, "baseline empty response", "none"

    stack = classify_spa_stack(response)
    if stack == "nextjs":
        return False, "Next.js detected (use nextjs pack, not standalone React)", "nextjs"
    if stack.startswith("react"):
        return True, "", stack
    # Weak fallback: React markers without full classify
    if is_react(response):
        return True, "", stack if stack != "none" else "react"
    return False, "no React SPA fingerprint", "none"


def ensure_react_target(module: Any, *, allow_nextjs: bool = False) -> Tuple[bool, str]:
    ok, reason, stack = probe_react_stack(module)
    if ok:
        return True, stack
    if allow_nextjs and stack == "nextjs":
        return True, stack
    if hasattr(module, "set_info"):
        module.set_info(reason=reason, confidence="low", stack=stack)
    return False, stack


def extract_script_urls(html: str, base_path: str = "/") -> List[str]:
    urls: List[str] = []
    for match in _SCRIPT_SRC_RE.finditer(html or ""):
        src = (match.group(1) or "").strip()
        if not src or src.startswith("data:"):
            continue
        if src.startswith("http://") or src.startswith("https://"):
            parsed = urlparse(src)
            path = parsed.path or ""
            if parsed.query:
                path = f"{path}?{parsed.query}"
            urls.append(path)
        else:
            urls.append(urljoin(base_path if base_path.endswith("/") else base_path + "/", src))
    # Prefer app bundles over vendor CDNs
    def score(u: str) -> int:
        low = u.lower()
        if "/static/js/" in low or "/assets/" in low:
            return 0
        if "react" in low or "main." in low or "index-" in low:
            return 1
        if "cdn." in low or "unpkg" in low or "jsdelivr" in low:
            return 9
        return 5

    urls = sorted(dict.fromkeys(urls), key=score)
    return urls[:12]


def look_like_sourcemap(body: str) -> bool:
    text = (body or "").lstrip()
    if not text.startswith("{"):
        return False
    try:
        data = json.loads(text[:2_000_000])
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    return "mappings" in data and ("sources" in data or "sourcesContent" in data)


def extract_sourcemap_url(js_body: str) -> str:
    match = _SOURCEMAP_RE.search(js_body or "")
    if not match:
        return ""
    return (match.group(1) or "").strip().rstrip("*/").strip()


def extract_client_env_keys(text: str) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen = set()
    for match in _ENV_KEY_RE.finditer(text or ""):
        key = match.group(1)
        val = match.group(2)[:80]
        if key in seen:
            continue
        seen.add(key)
        found.append({"key": key, "sample": val})
        if len(found) >= 20:
            break
    return found


def look_like_dotenv(body: str) -> bool:
    text = body or ""
    if "<html" in text[:500].lower():
        return False
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if len(lines) < 1:
        return False
    hits = 0
    interesting = 0
    for ln in lines[:80]:
        if _DOTENV_LINE_RE.match(ln):
            hits += 1
            if any(p in ln for p in ("REACT_APP_", "VITE_", "NEXT_PUBLIC_", "API_KEY", "SECRET", "TOKEN", "PASSWORD")):
                interesting += 1
    return hits >= 2 or (hits >= 1 and interesting >= 1)


def summarize_dotenv_keys(body: str) -> List[str]:
    keys: List[str] = []
    for match in _DOTENV_LINE_RE.finditer(body or ""):
        key = match.group(1)
        if key not in keys:
            keys.append(key)
        if len(keys) >= 30:
            break
    return keys


def stack_label(stack: str) -> str:
    return {
        "nextjs": "Next.js",
        "react_cra": "React (CRA)",
        "react_vite": "React (Vite)",
        "react": "React",
    }.get(stack, stack or "unknown")


__all__ = [
    "probe_react_stack",
    "ensure_react_target",
    "extract_script_urls",
    "look_like_sourcemap",
    "extract_sourcemap_url",
    "extract_client_env_keys",
    "look_like_dotenv",
    "summarize_dotenv_keys",
    "stack_label",
    "evidence_react",
    "is_react",
    "is_nextjs",
    "classify_spa_stack",
]
