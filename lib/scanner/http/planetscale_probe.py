#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PlanetScale service token and branch enumeration probes."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from lib.scanner.http.vibe_secrets_probe import mask_secret

_PSCALE_URL_RE = re.compile(
    r"(?i)(mysql://[^\s\"'<>]+@[a-z0-9.-]+\.psdb\.cloud[^\s\"'<>]*|https://[^\s\"'<>]+@[a-z0-9.-]+\.psdb\.cloud[^\s\"'<>]*)",
)
_PSCALE_TOKEN_RE = re.compile(r"\bpscale_tkn_[A-Za-z0-9_-]{20,}\b")
_PSCALE_ID_RE = re.compile(r"\bpscale_tkn_[A-Za-z0-9_-]{10,}\b")


def discover_planetscale_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _PSCALE_URL_RE.finditer(body):
        creds["database_url"] = match.group(1).strip()
    for match in re.finditer(
        r"(?i)(?:PLANETSCALE_(?:DATABASE_URL|CONNECTION_STRING|SERVICE_TOKEN|TOKEN))\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        val = match.group(1).strip()
        if val.startswith("pscale_tkn_"):
            creds["service_token"] = val
        elif "psdb.cloud" in val:
            creds["database_url"] = val
    for match in _PSCALE_TOKEN_RE.finditer(body):
        creds["service_token"] = match.group(0)
    for match in re.finditer(
        r"(?i)(?:PLANETSCALE_(?:ORG|ORGANIZATION|DATABASE|DB))\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        line = match.group(0).upper()
        val = match.group(1).strip()
        if "ORG" in line:
            creds["organization"] = val
        else:
            creds["database"] = val
    return creds


def parse_planetscale_url(database_url: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    try:
        parsed = urlparse(database_url.replace("https://", "mysql://", 1))
        host = parsed.hostname or ""
        info["host"] = host
        if host.endswith(".psdb.cloud"):
            parts = host.split(".")
            if len(parts) >= 3:
                info["branch_hint"] = parts[0]
                info["database_hint"] = parts[1] if len(parts) > 3 else ""
    except Exception:
        pass
    return info


def enum_planetscale_organizations(
    session,
    service_token: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = "https://api.planetscale.com/v1/organizations"
    headers = {"Authorization": service_token, "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "planetscale", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "planetscale", "ok": False, "detail": "token_rejected"}
    if response.status_code != 200:
        return {"platform": "planetscale", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "planetscale", "ok": False, "detail": "invalid_json"}
    orgs = data.get("data") if isinstance(data, dict) else data
    names = [str(o.get("name") or "") for o in (orgs or [])[:10] if isinstance(o, dict)]
    return {
        "platform": "planetscale",
        "ok": True,
        "kind": "planetscale_orgs_listed",
        "organizations": names,
        "count": len(orgs or []),
        "severity": "critical",
    }


def enum_planetscale_branches(
    session,
    service_token: str,
    organization: str,
    database: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    org = organization.strip()
    db = database.strip()
    url = f"https://api.planetscale.com/v1/organizations/{org}/databases/{db}/branches"
    headers = {"Authorization": service_token, "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "planetscale", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "planetscale", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "planetscale", "ok": False, "detail": "invalid_json"}
    branches = data.get("data") if isinstance(data, dict) else data
    names = [str(b.get("name") or "") for b in (branches or [])[:15] if isinstance(b, dict)]
    return {
        "platform": "planetscale",
        "ok": True,
        "kind": "planetscale_branches_listed",
        "organization": org,
        "database": db,
        "branches": names,
        "count": len(branches or []),
        "severity": "critical",
    }


def enumerate_planetscale(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    service_token: str = "",
    organization: str = "",
    database: str = "",
    database_url: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_planetscale_credentials(homepage_html or "")
    if service_token:
        creds["service_token"] = service_token
    if organization:
        creds["organization"] = organization
    if database:
        creds["database"] = database
    if database_url:
        creds["database_url"] = database_url

    findings: List[Dict[str, Any]] = []
    url = creds.get("database_url") or ""
    if url:
        meta = parse_planetscale_url(url)
        findings.append(
            {
                "platform": "planetscale",
                "ok": True,
                "kind": "planetscale_database_url_discovered",
                "url_masked": mask_secret(url),
                "branch_hint": meta.get("branch_hint"),
                "host": meta.get("host"),
                "severity": "critical",
            }
        )
        creds.setdefault("database", meta.get("database_hint", ""))
        if meta.get("branch_hint") and not creds.get("organization"):
            pass

    token = creds.get("service_token") or ""
    if token:
        orgs = enum_planetscale_organizations(session, token, verify_ssl=verify_ssl)
        orgs["token_masked"] = mask_secret(token)
        if orgs.get("ok"):
            findings.append(orgs)
            org = creds.get("organization") or ""
            db = creds.get("database") or ""
            if not org and orgs.get("organizations"):
                org = orgs["organizations"][0]
            if org and db:
                findings.append(
                    enum_planetscale_branches(session, token, org, db, verify_ssl=verify_ssl)
                )
            elif org and orgs.get("ok"):
                # Try list databases for first org
                try:
                    resp = session.get(
                        f"https://api.planetscale.com/v1/organizations/{org}/databases",
                        headers={"Authorization": token},
                        timeout=12,
                        verify=verify_ssl,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        dbs = data.get("data") if isinstance(data, dict) else []
                        if dbs and isinstance(dbs[0], dict):
                            db_name = str(dbs[0].get("name") or "")
                            if db_name:
                                findings.append(
                                    enum_planetscale_branches(
                                        session, token, org, db_name, verify_ssl=verify_ssl
                                    )
                                )
                except Exception:
                    pass
        else:
            findings.append(orgs)

    return findings, creds


__all__ = [
    "discover_planetscale_credentials",
    "enumerate_planetscale",
    "enum_planetscale_branches",
    "enum_planetscale_organizations",
]
