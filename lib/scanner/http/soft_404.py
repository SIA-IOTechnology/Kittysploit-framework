#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Soft-404 detection for HTTP scanners.

Catches two common false-positive patterns:
1. Catch-all / SPA hosts that return the homepage for every path.
2. Custom error pages (HTTP 200 "Not Found") that differ from ``/`` but are
   identical for any missing path (ABCya-style branded 404s).

Technique: fingerprint ``/`` *and* a random canary path, then reject probes that
match either baseline (or look like a generic 404 page).
"""

from __future__ import annotations

import hashlib
import re
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_LOCK = threading.RLock()

# origin -> Fingerprint of GET /
_INDEX_BASELINES: Dict[str, "Fingerprint"] = {}
# origin -> Fingerprint of GET /random-canary (custom soft-404 page)
_CANARY_BASELINES: Dict[str, "Fingerprint"] = {}
# origin -> canary path used
_CANARY_PATHS: Dict[str, str] = {}

# Body/title signals that a 200 response is actually a not-found page.
_NOT_FOUND_TITLE = re.compile(
    r"\b(404|not\s*found|page\s+not\s+found|error\s*404|fichier introuvable|"
    r"page\s+introuvable|doesn'?t\s+exist|can'?t\s+be\s+found|could\s+not\s+be\s+found)\b",
    re.I,
)
# Per-path canonical / OG tags on SPA catch-alls (e.g. href="https://site/.env").
_SPA_META_RE = re.compile(
    r"<link\b[^>]*\brel=[\"']canonical[\"'][^>]*>"
    r"|<meta\b[^>]*\bproperty=[\"']og:(?:url|title)[\"'][^>]*>"
    r"|<meta\b[^>]*\bname=[\"']twitter:(?:url|title)[\"'][^>]*>",
    re.I,
)


def strip_spa_path_variants(body: str, path: str = "") -> str:
    """Drop SPA meta tags (and optional path echoes) before shell comparison."""
    text = str(body or "")
    text = _SPA_META_RE.sub("", text)
    path_norm = str(path or "").strip()
    if path_norm and path_norm != "/":
        for variant in {path_norm, path_norm.rstrip("/"), path_norm.lstrip("/")}:
            if variant and len(variant) > 1:
                text = text.replace(variant, "/")
    return text


_NOT_FOUND_BODY = re.compile(
    r"(?:"
    r"not\s+found|"
    r"page\s+not\s+found|"
    r"content\s+can'?t\s+be\s+found|"
    r"content\s+could\s+not\s+be\s+found|"
    r"doesn'?t\s+exist|"
    r"no\s+longer\s+exists|"
    r"erreur\s*404|"
    r"page\s+introuvable|"
    r"fichier\s+introuvable|"
    r"the\s+requested\s+url\s+was\s+not\s+found|"
    r"this\s+page\s+isn'?t\s+available"
    r")",
    re.I,
)


@dataclass(frozen=True)
class Fingerprint:
    status: int
    length: int
    digest: str
    title: str
    ctype: str
    head_digest: str
    shell_digest: str = ""

    def exact_match(self, other: "Fingerprint") -> bool:
        return self.digest == other.digest and self.status == other.status

    def spa_shell_match(self, other: "Fingerprint") -> bool:
        """Same HTML shell after stripping per-path canonical/OG meta tags."""
        if not self.shell_digest or not other.shell_digest:
            return False
        if self.shell_digest != other.shell_digest:
            return False
        if self.status == other.status:
            return True
        # Redirect hop vs final 200 SPA page on the same host.
        return self.status in (200, 301, 302, 307, 308) and other.status in (
            200,
            301,
            302,
            307,
            308,
        )

    def near_match(self, other: "Fingerprint") -> bool:
        """Same status + similar size + same title/head — typical soft-404."""
        if self.spa_shell_match(other):
            return True
        if self.status != other.status:
            return False
        if self.digest == other.digest:
            return True
        if self.head_digest and self.head_digest == other.head_digest:
            return True
        if self.title and other.title and self.title == other.title:
            a, b = self.length, other.length
            if a <= 0 or b <= 0:
                return False
            if abs(a - b) / float(max(a, b)) <= 0.08:
                return True
        if "html" in (self.ctype or "") or "html" in (other.ctype or ""):
            a, b = self.length, other.length
            if a > 500 and b > 500 and abs(a - b) / float(max(a, b)) <= 0.02:
                if self.head_digest == other.head_digest:
                    return True
        return False


def clear_baselines() -> None:
    with _LOCK:
        _INDEX_BASELINES.clear()
        _CANARY_BASELINES.clear()
        _CANARY_PATHS.clear()


def make_canary_path() -> str:
    return f"/ks-soft404-{secrets.token_hex(8)}"


def remember_canary_path(origin: str, path: str) -> None:
    if not origin or not path:
        return
    with _LOCK:
        _CANARY_PATHS[origin] = path


def origin_key_from_url(url: str) -> str:
    parts = urlparse(str(url or ""))
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}:{int(port)}"


def origin_key_from_parts(scheme: str, host: str, port: int) -> str:
    scheme = (scheme or "http").lower()
    host = (host or "").lower().split(":")[0]
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        port_i = 443 if scheme == "https" else 80
    return f"{scheme}://{host}:{port_i}"


def _normalize_body(body: str) -> str:
    return " ".join(str(body or "").split())


def _extract_title(body: str) -> str:
    m = _TITLE_RE.search(body or "")
    if not m:
        return ""
    return " ".join(m.group(1).split())[:160].lower()


def fingerprint_text(
    *,
    status: int,
    body: str,
    content_type: str = "",
) -> Fingerprint:
    raw = str(body or "")
    normalized = _normalize_body(raw)
    digest = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()
    head = normalized[:2048]
    head_digest = hashlib.sha256(head.encode("utf-8", errors="replace")).hexdigest()
    shell_normalized = _normalize_body(strip_spa_path_variants(raw))
    shell_digest = hashlib.sha256(
        shell_normalized.encode("utf-8", errors="replace")
    ).hexdigest()
    ctype = str(content_type or "").lower()
    return Fingerprint(
        status=int(status or 0),
        length=len(raw),
        digest=digest,
        title=_extract_title(raw),
        ctype=ctype,
        head_digest=head_digest,
        shell_digest=shell_digest,
    )


def fingerprint_response(response: Any) -> Optional[Fingerprint]:
    if response is None:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    headers = getattr(response, "headers", None) or {}
    ctype = ""
    try:
        ctype = str(headers.get("Content-Type") or headers.get("content-type") or "")
    except Exception:
        ctype = ""
    return fingerprint_text(status=status, body=body, content_type=ctype)


def register_baseline(origin: str, fp: Fingerprint) -> None:
    """Register GET / fingerprint."""
    if not origin or not fp:
        return
    with _LOCK:
        _INDEX_BASELINES[origin] = fp


def register_baseline_from_response(origin: str, response: Any) -> Optional[Fingerprint]:
    fp = fingerprint_response(response)
    if fp:
        register_baseline(origin, fp)
    return fp


def register_canary_from_response(
    origin: str,
    response: Any,
    *,
    path: str = "",
) -> Optional[Fingerprint]:
    """Register fingerprint of a known-missing path (custom soft-404 page)."""
    fp = fingerprint_response(response)
    if not origin or not fp:
        return None
    with _LOCK:
        _CANARY_BASELINES[origin] = fp
        if path:
            _CANARY_PATHS[origin] = path
    return fp


def get_baseline(origin: str) -> Optional[Fingerprint]:
    with _LOCK:
        return _INDEX_BASELINES.get(origin)


def get_canary(origin: str) -> Optional[Fingerprint]:
    with _LOCK:
        return _CANARY_BASELINES.get(origin)


def get_canary_path(origin: str) -> str:
    with _LOCK:
        return _CANARY_PATHS.get(origin) or ""


def looks_like_not_found_page(response: Any) -> bool:
    """Heuristic: body/title scream 404 even when status is 200."""
    if response is None:
        return False
    status = int(getattr(response, "status_code", 0) or 0)
    if status in (404, 410):
        return True
    body = str(getattr(response, "text", "") or "")
    if not body:
        return False
    title = _extract_title(body)
    if title and _NOT_FOUND_TITLE.search(title):
        return True
    # Only apply body heuristic on HTML-ish responses to avoid killing JSON APIs.
    headers = getattr(response, "headers", None) or {}
    try:
        ctype = str(headers.get("Content-Type") or headers.get("content-type") or "").lower()
    except Exception:
        ctype = ""
    sample = body[:4000]
    is_html = "html" in ctype or "<html" in sample.lower() or "<!doctype" in sample.lower()
    if not is_html:
        return False
    # Require a fairly clear not-found phrase in the first chunk.
    if _NOT_FOUND_BODY.search(sample) and (
        _NOT_FOUND_TITLE.search(title) or status in (200, 404, 410)
    ):
        # Avoid matching marketing copy that casually says "not found" once —
        # require title hit OR multiple body hits OR short error-ish page.
        hits = len(_NOT_FOUND_BODY.findall(sample))
        if title and _NOT_FOUND_TITLE.search(title):
            return True
        if hits >= 2:
            return True
        if hits >= 1 and len(body) < 12000 and (
            "go to home" in sample.lower()
            or "back to home" in sample.lower()
            or "homepage" in sample.lower()
            or "home page" in sample.lower()
        ):
            return True
    return False


def matches_baseline(fp: Fingerprint, baseline: Optional[Fingerprint]) -> bool:
    if not fp or not baseline:
        return False
    return baseline.exact_match(fp) or baseline.near_match(fp)


def is_soft_404(
    response: Any,
    *,
    origin: str = "",
    path: str = "",
    baseline: Optional[Fingerprint] = None,
    canary: Optional[Fingerprint] = None,
) -> bool:
    """
    True when ``response`` is a soft-404 / custom not-found / index clone.

    Root path ``/`` is never treated as soft-404 of itself.
    """
    path_norm = str(path or "").strip() or "/"
    if path_norm == "/":
        return False
    if response is None:
        return False

    status = int(getattr(response, "status_code", 0) or 0)
    if status in (404, 410):
        return True
    if looks_like_not_found_page(response):
        return True

    fp = fingerprint_response(response)
    if not fp:
        return False

    index_fp = baseline if baseline is not None else (get_baseline(origin) if origin else None)
    canary_fp = canary if canary is not None else (get_canary(origin) if origin else None)

    if matches_baseline(fp, index_fp):
        return True
    if matches_baseline(fp, canary_fp):
        return True
    return False


# Back-compat alias used by modules / Http_client.
def is_same_as_index(
    response: Any,
    *,
    origin: str = "",
    path: str = "",
    baseline: Optional[Fingerprint] = None,
) -> bool:
    return is_soft_404(
        response,
        origin=origin,
        path=path,
        baseline=baseline,
    )


def annotate_response(response: Any, *, origin: str, path: str) -> Any:
    """Attach ``ks_same_as_index`` / ``ks_soft_404`` on the response object."""
    if response is None:
        return response
    try:
        soft = is_soft_404(response, origin=origin, path=path)
        try:
            setattr(response, "ks_same_as_index", soft)
            setattr(response, "ks_soft_404", soft)
        except Exception:
            pass
    except Exception:
        try:
            setattr(response, "ks_same_as_index", False)
            setattr(response, "ks_soft_404", False)
        except Exception:
            pass
    return response


def finding_looks_like_index_clone(module: Any, dynamic_info: Optional[Dict[str, Any]] = None) -> bool:
    """
    Best-effort veto for a positive scanner hit that is a soft-404.

    Uses annotated last response, then cached GET for finding path vs index/canary.
    """
    info = dynamic_info if isinstance(dynamic_info, dict) else {}
    path = str(info.get("path") or getattr(module, "_ks_last_http_path", "") or "").strip()
    if not path or path == "/":
        return False

    last = getattr(module, "_ks_last_http_response", None)
    last_path = str(getattr(module, "_ks_last_http_path", "") or "").strip()
    origin = str(getattr(module, "_ks_http_origin", "") or "").strip()

    if last is not None and (not last_path or last_path == path):
        if bool(getattr(last, "ks_soft_404", None) or getattr(last, "ks_same_as_index", False)):
            return True
        if origin and is_soft_404(last, origin=origin, path=path):
            return True

    try:
        from lib.scanner.cache import get_cache, is_cache_enabled

        if not is_cache_enabled():
            return False
        cache = get_cache()
        url = _module_url(module, path)
        root_url = _module_url(module, "/")
        if not url or not root_url:
            return False
        origin = origin or origin_key_from_url(root_url)
        probe = cache.get("GET", url)
        root = cache.get("GET", root_url)
        if root is not None and not get_baseline(origin):
            register_baseline_from_response(origin, root)
        canary_path = get_canary_path(origin)
        if canary_path and not get_canary(origin):
            canary_url = _module_url(module, canary_path)
            canary_resp = cache.get("GET", canary_url) if canary_url else None
            if canary_resp is not None:
                register_canary_from_response(origin, canary_resp, path=canary_path)
        if probe is None:
            return False
        return is_soft_404(probe, origin=origin, path=path)
    except Exception:
        return False


def _module_url(module: Any, path: str) -> str:
    def _opt(name: str, default: Any = None) -> Any:
        v = getattr(module, name, default)
        if hasattr(v, "value"):
            return v.value
        return v

    target = _opt("target") or _opt("rhost") or ""
    if not target:
        return ""
    from lib.scanner.target_utils import normalize_scanner_target

    host, url_port, url_ssl = normalize_scanner_target(str(target))
    port = _opt("port") or _opt("rport") or url_port
    try:
        port_i = int(port) if port not in (None, "") else (443 if url_ssl else 80)
    except (TypeError, ValueError):
        port_i = 443
    if url_ssl is not None:
        scheme = "https" if url_ssl else "http"
    else:
        ssl = _opt("ssl", False)
        if hasattr(ssl, "value"):
            ssl = ssl.value
        scheme = "https" if bool(ssl) or port_i == 443 else "http"
    path_str = path if str(path).startswith("/") else f"/{path}"
    return f"{scheme}://{host}:{port_i}{path_str}"
