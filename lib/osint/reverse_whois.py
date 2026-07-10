#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reverse WHOIS / registrant pivot helpers."""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import quote


def _clean_lines(text: str) -> List[str]:
    domains: List[str] = []
    for line in (text or "").splitlines():
        value = line.strip().lower()
        if not value or value.startswith(("#", "//")):
            continue
        if " " in value:
            value = value.split()[0]
        if "." in value and re.match(r"^[a-z0-9][a-z0-9\.-]+\.[a-z]{2,}$", value):
            domains.append(value)
    return sorted(set(domains))


def reverse_whois_hackertarget(query: str, http_get, timeout: float = 12.0) -> Dict[str, object]:
    """Best-effort reverse WHOIS via HackerTarget public API (rate-limited)."""
    q = str(query or "").strip()
    if not q:
        return {"error": "empty_query", "domains": []}
    url = f"https://api.hackertarget.com/reversewhois/?q={quote(q)}"
    resp = http_get(url, timeout)
    if not resp:
        return {"error": "request_failed", "query": q, "domains": []}
    body = (getattr(resp, "text", None) or "").strip()
    if not body:
        return {"error": "empty_response", "query": q, "domains": []}
    lower = body.lower()
    if "error" in lower and "no dns" not in lower:
        if "api count exceeded" in lower or "too many" in lower:
            return {"error": "rate_limited", "query": q, "domains": []}
        if "no matches" in lower or "no results" in lower:
            return {"query": q, "domains": [], "count": 0}
        return {"error": body.splitlines()[0], "query": q, "domains": []}
    domains = _clean_lines(body)
    return {"query": q, "domains": domains, "count": len(domains), "source": "hackertarget"}


def reverse_whois_rdap_org_hint(org_name: str, http_get, timeout: float = 12.0) -> Dict[str, object]:
    """
    Lightweight RDAP entity lookup hint. Full reverse WHOIS is registry-limited;
    this returns entity metadata when available.
    """
    org = str(org_name or "").strip()
    if not org:
        return {"error": "empty_query"}
    url = f"https://rdap.org/entity?name={quote(org)}"
    resp = http_get(url, timeout)
    if not resp or getattr(resp, "status_code", 0) not in (200, 404):
        return {"error": "rdap_request_failed", "query": org}
    if resp.status_code == 404:
        return {"query": org, "entity": {}, "domains": [], "count": 0, "source": "rdap"}
    try:
        data = resp.json()
    except Exception:
        return {"error": "rdap_parse_failed", "query": org}
    labels = []
    for key in ("handle", "fn", "email", "org"):
        if data.get(key):
            labels.append(str(data.get(key)))
    return {
        "query": org,
        "entity": data,
        "labels": labels,
        "domains": [],
        "count": 0,
        "source": "rdap",
        "note": "RDAP entity lookup does not return full domain inventory",
    }
