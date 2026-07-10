#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared helpers for passive web surface OSINT modules."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

DOMAIN_RX = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$",
    re.I,
)


def normalize_domain(value: str) -> Optional[str]:
    domain = str(value or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/", 1)[0].strip(".")
    if not domain or "." not in domain or "@" in domain:
        return None
    if not DOMAIN_RX.match(domain):
        return None
    return domain


def normalize_base_url(value: str) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        return None
    scheme = (parsed.scheme or "https").lower()
    return f"{scheme}://{parsed.hostname}"


def http_get_via_client(module: Any, url: str, timeout_seconds: float = 15.0, headers: Optional[Dict[str, str]] = None):
    """Perform GET using an Auxiliary+Http_client module instance."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    scheme = (parsed.scheme or "https").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    old_target = getattr(module, "target", "")
    old_port = getattr(module, "port", 443)
    old_ssl = getattr(module, "ssl", True)
    try:
        module.target = host
        module.port = int(port)
        module.ssl = scheme == "https"
        return module.http_request(
            method="GET",
            path=path,
            allow_redirects=True,
            timeout=timeout_seconds,
            headers=headers or {},
        )
    except Exception:
        return None
    finally:
        module.target = old_target
        module.port = old_port
        module.ssl = old_ssl


def fetch_with_https_fallback(module: Any, url: str, timeout_seconds: float = 15.0, headers: Optional[Dict[str, str]] = None):
    """Try HTTPS first, then HTTP fallback."""
    resp = http_get_via_client(module, url, timeout_seconds, headers=headers)
    if resp is not None:
        return resp, url, "https"
    if url.startswith("https://"):
        fallback = "http://" + url[8:]
        resp = http_get_via_client(module, fallback, timeout_seconds, headers=headers)
        if resp is not None:
            return resp, fallback, "http_fallback"
    return None, url, "failed"


def parse_security_txt(text: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {
        "contact": [],
        "acknowledgments": [],
        "policy": [],
        "hiring": [],
        "encryption": [],
        "other": [],
    }
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        bucket = out.get(key, out["other"])
        bucket.append(value)
    return out


def parse_robots_txt(text: str) -> Dict[str, Any]:
    disallow: List[str] = []
    allow: List[str] = []
    sitemaps: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallow.append(path)
        elif low.startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                allow.append(path)
        elif low.startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            if sm:
                sitemaps.append(sm)
    return {"disallow": disallow, "allow": allow, "sitemaps": sitemaps}


def parse_sitemap_urls(text: str, base_url: str, limit: int = 200) -> List[str]:
    urls: List[str] = []
    text = (text or "").strip()
    if not text:
        return urls
    try:
        root = ElementTree.fromstring(text)
    except Exception:
        return urls

    tag = root.tag.lower()
    if tag.endswith("sitemapindex"):
        for loc in root.iter():
            if loc.tag.lower().endswith("loc") and loc.text:
                urls.append(loc.text.strip())
                if len(urls) >= limit:
                    break
        return urls

    for loc in root.iter():
        if loc.tag.lower().endswith("loc") and loc.text:
            href = loc.text.strip()
            if href:
                urls.append(href)
            if len(urls) >= limit:
                break
    if not urls and base_url:
        return [base_url]
    return urls


def extract_html_title(html: str) -> str:
    match = re.search(r"<title[^>]*>([^<]{1,200})</title>", html or "", re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def discover_favicon_urls(html: str, base_url: str) -> List[str]:
    found: List[str] = []
    for match in re.finditer(
        r"""<link[^>]+rel=["'](?:shortcut\s+)?icon["'][^>]*>""",
        html or "",
        re.I,
    ):
        tag = match.group(0)
        href_match = re.search(r"""href=["']([^"']+)["']""", tag, re.I)
        if href_match:
            found.append(urljoin(base_url, href_match.group(1)))
    default = urljoin(base_url, "/favicon.ico")
    if default not in found:
        found.append(default)
    return found[:6]
