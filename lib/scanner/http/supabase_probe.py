#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract and classify Supabase credentials leaked in client-side assets."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

from lib.scanner.http.react_probe import extract_script_urls

_SUPABASE_URL_RE = re.compile(
    r"https://([a-z0-9-]{8,})\.supabase\.co",
    re.I,
)
_SUPABASE_JWT_RE = re.compile(
    r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
_SUPABASE_NAMED_RE = re.compile(
    r"""(?ix)
    ((?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_)?SUPABASE_
    (?:URL|ANON_KEY|SERVICE_ROLE_KEY|PUBLISHABLE_KEY|SECRET_KEY|KEY))
    \s*[=:]\s*["']([^"']+)["']
    """
)
_CREATE_CLIENT_RE = re.compile(
    r"""createClient\s*\(\s*["'](https://[^"']+\.supabase\.co)["']\s*,\s*["']([^"']+)["']""",
    re.I,
)
_SERVICE_ROLE_NAME_RE = re.compile(
    r"(?i)SUPABASE_(?:SERVICE_ROLE|SECRET)(?:_KEY)?",
)

_ENV_PATHS = (
    "/",
    "/env.js",
    "/config.js",
    "/config/env.js",
    "/config/runtime-env.js",
    "/runtime-env.js",
    "/env-config.js",
    "/firebase-config.js",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
)


def _b64url_json(segment: str) -> Optional[Dict[str, Any]]:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def decode_supabase_jwt(token: str) -> Optional[Dict[str, Any]]:
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    payload = _b64url_json(parts[1])
    if not payload:
        return None
    if payload.get("iss") not in ("supabase", "supabase-demo"):
        role = payload.get("role")
        if role not in ("anon", "service_role", "authenticated"):
            return None
    return payload


def classify_supabase_key(token: str, *, var_name: str = "") -> str:
    """Return anon, service_role, or unknown."""
    if _SERVICE_ROLE_NAME_RE.search(var_name or ""):
        return "service_role"
    payload = decode_supabase_jwt(token)
    if not payload:
        return "unknown"
    role = str(payload.get("role") or "").strip().lower()
    if role in ("anon", "service_role", "authenticated"):
        return role
    return "unknown"


def mask_token(token: str) -> str:
    token = token or ""
    if len(token) <= 16:
        return token[:4] + "…"
    return f"{token[:10]}…{token[-6:]}"


def extract_supabase_findings(text: str, *, source: str = "") -> List[Dict[str, Any]]:
    """Parse HTML/JS/text for Supabase URLs, JWT keys, and named env assignments."""
    body = text or ""
    findings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()

    def add(kind: str, project_ref: str, token: str, var_name: str = "") -> None:
        role = classify_supabase_key(token, var_name=var_name) if token else "info"
        key = (kind, project_ref or "", token[:48], var_name)
        if key in seen:
            return
        seen.add(key)
        payload = decode_supabase_jwt(token) or {} if token else {}
        findings.append(
            {
                "kind": kind,
                "source": source,
                "project_ref": project_ref or str(payload.get("ref") or ""),
                "role": role,
                "var_name": var_name,
                "token": token,
                "token_masked": mask_token(token) if token else "",
                "iss": payload.get("iss"),
            }
        )

    for match in _SUPABASE_NAMED_RE.finditer(body):
        var_name = (match.group(1) or "").strip()
        value = (match.group(2) or "").strip()
        if ".supabase.co" in value.lower():
            ref_match = _SUPABASE_URL_RE.search(value)
            if ref_match:
                add("env_url", ref_match.group(1), "", var_name=var_name)
            continue
        if value.startswith("eyJ"):
            ref = ""
            payload = decode_supabase_jwt(value)
            if payload:
                ref = str(payload.get("ref") or "")
            add("env_key", ref, value, var_name=var_name)

    for url_match, token in _CREATE_CLIENT_RE.findall(body):
        ref_match = _SUPABASE_URL_RE.search(url_match)
        ref = ref_match.group(1) if ref_match else ""
        add("create_client", ref, token)

    for token in _SUPABASE_JWT_RE.findall(body):
        payload = decode_supabase_jwt(token)
        if not payload:
            continue
        ref = str(payload.get("ref") or "")
        add("jwt", ref, token)

    for ref in _SUPABASE_URL_RE.findall(body):
        if not any(f.get("project_ref") == ref for f in findings):
            findings.append(
                {
                    "kind": "url_only",
                    "source": source,
                    "project_ref": ref,
                    "role": "info",
                    "var_name": "",
                    "token_masked": "",
                    "iss": None,
                }
            )

    return findings


def worst_severity(findings: List[Dict[str, Any]]) -> str:
    roles = {str(f.get("role") or "").lower() for f in findings}
    if "service_role" in roles:
        return "critical"
    if any(r in roles for r in ("anon", "authenticated", "unknown")):
        return "high"
    if findings:
        return "medium"
    return "info"


def collect_http_bodies(http_request, html_path: str = "/") -> List[Tuple[str, str]]:
    """Fetch homepage, env endpoints, and a few JS bundles."""
    bodies: List[Tuple[str, str]] = []
    seen_paths: Set[str] = set()

    def fetch(path: str) -> None:
        if path in seen_paths:
            return
        seen_paths.add(path)
        response = http_request(method="GET", path=path, allow_redirects=path == "/")
        if not response or response.status_code != 200:
            return
        text = response.text or ""
        if not text.strip():
            return
        bodies.append((path, text))

    for path in _ENV_PATHS:
        fetch(path)

    homepage = next((text for p, text in bodies if p == "/"), "")
    if homepage:
        for script_path in extract_script_urls(homepage, "/")[:10]:
            fetch(script_path)

    return bodies


def validate_supabase_key(project_ref: str, api_key: str, session, *, verify_ssl: bool = True) -> Tuple[bool, str]:
    """Probe Supabase REST root with the discovered key."""
    if not project_ref or not api_key:
        return False, "missing_ref_or_key"
    url = f"https://{project_ref}.supabase.co/rest/v1/"
    headers = supabase_headers(api_key)
    try:
        response = session.get(url, headers=headers, timeout=8, verify=verify_ssl)
    except Exception as exc:
        return False, f"probe_error:{exc}"
    text = (response.text or "")[:400]
    if response.status_code == 200 and ("swagger" in text.lower() or "openapi" in text.lower() or "paths" in text):
        return True, "rest_api_live"
    if response.status_code in (200, 204):
        return True, f"http_{response.status_code}"
    if response.status_code == 401:
        return False, "key_rejected"
    return response.status_code < 500, f"http_{response.status_code}"


def supabase_headers(api_key: str) -> Dict[str, str]:
    return {
        "apikey": api_key,
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }


def supabase_base_url(project_ref: str) -> str:
    return f"https://{(project_ref or '').strip()}.supabase.co"


def parse_openapi_tables(openapi_body: Any) -> List[str]:
    tables: List[str] = []
    if not isinstance(openapi_body, dict):
        return tables
    paths = openapi_body.get("paths") or {}
    if not isinstance(paths, dict):
        return tables
    for path in paths.keys():
        name = str(path or "").strip().strip("/")
        if not name or name.startswith("rpc/"):
            continue
        if "/" in name:
            continue
        tables.append(name)
    return sorted(set(tables))


def fetch_openapi_schema(
    project_ref: str,
    api_key: str,
    session,
    *,
    verify_ssl: bool = True,
) -> Tuple[Optional[Dict[str, Any]], str]:
    url = f"{supabase_base_url(project_ref)}/rest/v1/"
    headers = dict(supabase_headers(api_key))
    headers["Accept"] = "application/openapi+json"
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return None, f"probe_error:{exc}"
    if response.status_code == 401:
        return None, "key_rejected"
    if response.status_code != 200:
        return None, f"http_{response.status_code}"
    try:
        data = response.json()
    except Exception:
        return None, "invalid_openapi_json"
    if isinstance(data, dict) and data.get("paths"):
        return data, "ok"
    return None, "missing_paths"


def probe_table_rows(
    project_ref: str,
    api_key: str,
    session,
    table: str,
    *,
    limit: int = 3,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    safe_table = re.sub(r"[^A-Za-z0-9_]", "", table or "")
    if not safe_table:
        return {"table": table, "readable": False, "detail": "invalid_table"}
    url = f"{supabase_base_url(project_ref)}/rest/v1/{safe_table}"
    headers = dict(supabase_headers(api_key))
    headers["Prefer"] = "count=exact"
    params = {"select": "*", "limit": str(max(1, min(limit, 10)))}
    try:
        response = session.get(
            url,
            headers=headers,
            params=params,
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return {"table": safe_table, "readable": False, "detail": f"probe_error:{exc}"}

    content_range = response.headers.get("Content-Range") or response.headers.get("content-range") or ""
    row_count_hint = ""
    if "/" in content_range:
        row_count_hint = content_range.split("/")[-1].strip()

    body_text = (response.text or "")[:4000]
    rows: List[Any] = []
    if response.status_code == 200:
        try:
            parsed = response.json()
            if isinstance(parsed, list):
                rows = parsed
        except Exception:
            pass

    readable = response.status_code == 200 and bool(rows)
    return {
        "table": safe_table,
        "readable": readable,
        "status": response.status_code,
        "rows_returned": len(rows),
        "total_hint": row_count_hint,
        "sample_columns": sorted(rows[0].keys())[:12] if rows and isinstance(rows[0], dict) else [],
        "detail": "rows_returned" if readable else body_text[:180],
    }


def list_storage_buckets(
    project_ref: str,
    api_key: str,
    session,
    *,
    verify_ssl: bool = True,
) -> Tuple[List[Dict[str, Any]], str]:
    url = f"{supabase_base_url(project_ref)}/storage/v1/bucket"
    try:
        response = session.get(
            url,
            headers=supabase_headers(api_key),
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return [], f"probe_error:{exc}"
    if response.status_code == 401:
        return [], "key_rejected"
    if response.status_code != 200:
        return [], f"http_{response.status_code}"
    try:
        data = response.json()
    except Exception:
        return [], "invalid_json"
    if not isinstance(data, list):
        return [], "unexpected_bucket_payload"
    buckets = []
    for item in data:
        if isinstance(item, dict):
            buckets.append(
                {
                    "id": item.get("id") or item.get("name"),
                    "name": item.get("name") or item.get("id"),
                    "public": bool(item.get("public")),
                }
            )
    return buckets, "ok"


def list_storage_objects(
    project_ref: str,
    api_key: str,
    session,
    bucket: str,
    *,
    limit: int = 20,
    verify_ssl: bool = True,
) -> Tuple[List[Dict[str, Any]], str]:
    bucket_name = (bucket or "").strip()
    if not bucket_name:
        return [], "invalid_bucket"
    url = f"{supabase_base_url(project_ref)}/storage/v1/object/list/{bucket_name}"
    payload = {"prefix": "", "limit": max(1, min(limit, 100)), "offset": 0}
    headers = dict(supabase_headers(api_key))
    headers["Content-Type"] = "application/json"
    try:
        response = session.post(
            url,
            headers=headers,
            json=payload,
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return [], f"probe_error:{exc}"
    if response.status_code == 401:
        return [], "key_rejected"
    if response.status_code not in (200, 201):
        return [], f"http_{response.status_code}"
    try:
        data = response.json()
    except Exception:
        return [], "invalid_json"
    if not isinstance(data, list):
        return [], "unexpected_object_payload"
    objects = []
    for item in data[:limit]:
        if isinstance(item, dict):
            objects.append(
                {
                    "name": item.get("name"),
                    "id": item.get("id"),
                    "metadata": item.get("metadata"),
                }
            )
    return objects, "ok"


def probe_public_storage_object(
    project_ref: str,
    bucket: str,
    object_path: str,
    session,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    bucket_name = (bucket or "").strip().strip("/")
    obj = (object_path or "").strip().lstrip("/")
    if not bucket_name or not obj:
        return {"accessible": False, "detail": "invalid_path"}
    url = f"{supabase_base_url(project_ref)}/storage/v1/object/public/{bucket_name}/{obj}"
    try:
        response = session.get(url, timeout=10, verify=verify_ssl)
    except Exception as exc:
        return {"accessible": False, "detail": f"probe_error:{exc}"}
    return {
        "accessible": response.status_code == 200,
        "status": response.status_code,
        "url": url,
        "detail": (response.text or "")[:120],
    }


DEFAULT_PUBLIC_BUCKETS = (
    "public",
    "uploads",
    "avatars",
    "images",
    "files",
    "assets",
    "media",
    "documents",
    "attachments",
    "profile-pictures",
    "user-uploads",
    "bucket",
)


def enumerate_auth_users(
    project_ref: str,
    api_key: str,
    session,
    *,
    per_page: int = 50,
    verify_ssl: bool = True,
) -> Tuple[List[Dict[str, Any]], str]:
    url = f"{supabase_base_url(project_ref)}/auth/v1/admin/users"
    params = {"page": 1, "per_page": max(1, min(per_page, 100))}
    try:
        response = session.get(
            url,
            headers=supabase_headers(api_key),
            params=params,
            timeout=12,
            verify=verify_ssl,
        )
    except Exception as exc:
        return [], f"probe_error:{exc}"
    if response.status_code == 401:
        return [], "key_rejected"
    if response.status_code == 403:
        return [], "forbidden_requires_service_role"
    if response.status_code != 200:
        return [], f"http_{response.status_code}"
    try:
        data = response.json()
    except Exception:
        return [], "invalid_json"
    users = data.get("users") if isinstance(data, dict) else None
    if not isinstance(users, list):
        return [], "unexpected_users_payload"
    sanitized = []
    for user in users[:per_page]:
        if not isinstance(user, dict):
            continue
        sanitized.append(
            {
                "id": user.get("id"),
                "email": user.get("email"),
                "phone": user.get("phone"),
                "created_at": user.get("created_at"),
                "confirmed_at": user.get("confirmed_at"),
            }
        )
    return sanitized, "ok"


__all__ = [
    "collect_http_bodies",
    "decode_supabase_jwt",
    "classify_supabase_key",
    "extract_supabase_findings",
    "mask_token",
    "validate_supabase_key",
    "worst_severity",
    "supabase_headers",
    "supabase_base_url",
    "parse_openapi_tables",
    "fetch_openapi_schema",
    "probe_table_rows",
    "list_storage_buckets",
    "list_storage_objects",
    "probe_public_storage_object",
    "enumerate_auth_users",
    "DEFAULT_PUBLIC_BUCKETS",
]
