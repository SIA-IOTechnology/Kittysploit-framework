#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Module search filters and facet helpers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from core.utils.module_static_metadata import infer_module_type_from_path, normalize_module_type


SUPPORTED_TYPES = {
    "analysis",
    "auxiliary",
    "backdoors",
    "browser_auxiliary",
    "browser_exploits",
    "docker_environment",
    "encoders",
    "encoder",
    "exploits",
    "exploit",
    "listeners",
    "listener",
    "transform",
    "transforms",
    "obfuscator",
    "obfuscators",
    "payloads",
    "payload",
    "post",
    "scanner",
    "shortcut",
    "workflow",
}

RELIABILITY_ALIASES = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
    "unknown": "unknown",
}

PROTOCOL_PATH_HINTS = (
    ("scanner/http/", "http"),
    ("auxiliary/scanner/http/", "http"),
    ("exploits/multi/http/", "http"),
    ("exploits/http/", "http"),
    ("scanner/ldap/", "ldap"),
    ("scanner/smb/", "smb"),
    ("scanner/ftp/", "ftp"),
    ("auxiliary/scanner/ftp/", "ftp"),
    ("scanner/ssh/", "ssh"),
    ("scanner/mysql/", "mysql"),
    ("post/mysql/", "mysql"),
    ("scanner/redis/", "redis"),
    ("post/redis/", "redis"),
    ("scanner/cloud/", "cloud"),
    ("scanner/telecom/", "telecom"),
    ("scanner/tcp/", "tcp"),
    ("scanner/ics/mqtt", "mqtt"),
    ("auxiliary/scanner/ics/mqtt", "mqtt"),
    ("listeners/iot/mqtt", "mqtt"),
    ("listeners/covert/dns", "dns"),
    ("auxiliary/osint/", "dns"),
    ("auxiliary/gather/brute_dns", "dns"),
    ("listeners/web/", "http"),
    ("listeners/multi/", "tcp"),
)


@dataclass
class ModuleSearchFilters:
    query: str = ""
    module_type: str = ""
    author: str = ""
    cve: str = ""
    tag: str = ""
    platform: str = ""
    protocol: str = ""
    reliability: str = ""
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    limit: int = 50

    def normalized_type(self) -> str:
        return normalize_module_type((self.module_type or "").strip())

    def normalized_reliability(self) -> str:
        value = (self.reliability or "").strip().lower()
        return RELIABILITY_ALIASES.get(value, value)

    def has_structured_filters(self) -> bool:
        return any(
            [
                self.module_type,
                self.author,
                self.cve,
                self.tag,
                self.platform,
                self.protocol,
                self.reliability,
                self.since,
                self.until,
            ]
        )

    def summary(self) -> str:
        parts = []
        if self.query:
            parts.append(f"query={self.query!r}")
        for label, value in (
            ("type", self.module_type),
            ("cve", self.cve),
            ("tag", self.tag),
            ("platform", self.platform),
            ("protocol", self.protocol),
            ("reliability", self.reliability),
            ("author", self.author),
        ):
            if value:
                parts.append(f"{label}={value!r}")
        if self.since:
            parts.append(f"since={self.since.date().isoformat()}")
        if self.until:
            parts.append(f"until={self.until.date().isoformat()}")
        return ", ".join(parts) if parts else "all modules"


def parse_date(value: str) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00").replace("+00:00", ""))
    except ValueError:
        return None


def normalize_platform(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = text.split(".")[-1]
    remap = {"multi": "multi", "all": "multi", "php": "php", "perl": "perl", "windows": "windows", "linux": "linux", "unix": "unix"}
    return remap.get(text, text)


def normalize_reliability(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return RELIABILITY_ALIASES.get(text, text)


def infer_platform_from_module_path(module_path: str) -> str:
    path = (module_path or "").lower().replace("\\", "/")
    if path.startswith("modules/"):
        path = path[len("modules/") :]
    hints = (
        ("/shell/linux/", "linux"),
        ("/linux/", "linux"),
        ("/windows/", "windows"),
        ("/android/", "android"),
        ("/php/", "php"),
        ("/gcp/", "cloud"),
        ("/aws/", "cloud"),
        ("/azure/", "cloud"),
        ("/ics/", "ics"),
        ("/adb/", "android"),
        ("/wp_", "php"),
        ("/wordpress", "php"),
    )
    for fragment, platform in hints:
        if fragment in path:
            return platform
    parts = path.split("/")
    if len(parts) >= 2 and parts[0] == "exploits":
        if parts[1] in {"linux", "windows", "android", "unix"}:
            return parts[1]
        if parts[1] in {"multi", "ctf"}:
            return "multi"
    if len(parts) >= 2 and parts[0] == "post" and parts[1] in {
        "mysql",
        "postgresql",
        "redis",
        "mongodb",
        "mssql",
        "http",
        "ftp",
        "ldap",
        "smb",
        "quic",
        "canbus",
        "elasticsearch",
        "email",
    }:
        return "multi"
    return ""


def infer_protocol_from_module_path(module_path: str) -> str:
    path = (module_path or "").lower().replace("\\", "/")
    if not path.startswith("modules/"):
        normalized = path
    else:
        normalized = path[len("modules/") :]
    for prefix, protocol in PROTOCOL_PATH_HINTS:
        if normalized.startswith(prefix):
            return protocol
    parts = normalized.split("/")
    if len(parts) >= 3 and parts[0] == "auxiliary" and parts[1] == "scanner":
        return parts[2]
    if len(parts) >= 2 and parts[0] == "post":
        return parts[1]
    if len(parts) >= 2 and parts[0] in {"scanner", "auxiliary", "exploits", "exploit", "listeners", "listener"}:
        candidate = parts[1]
        if candidate not in {"multi", "linux", "windows", "unix", "scanner"}:
            return candidate
    if len(parts) >= 3 and parts[1] in {"multi", "linux", "windows", "unix"}:
        return parts[2]
    return ""


def extract_search_facets(meta: Dict[str, Any], module_path: str) -> Dict[str, str]:
    platform = normalize_platform(meta.get("platform")) or infer_platform_from_module_path(module_path)
    protocol = str(meta.get("protocol") or "").strip().lower() or infer_protocol_from_module_path(module_path)
    reliability = normalize_reliability(meta.get("reliability") or meta.get("severity") or meta.get("confidence"))
    return {
        "platform": platform,
        "protocol": protocol,
        "reliability": reliability,
    }


def module_record_tags(record: Dict[str, Any]) -> List[str]:
    raw = record.get("tags")
    if isinstance(raw, list):
        return [str(item).lower() for item in raw if str(item).strip()]
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(item).lower() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass
        return [text.lower()]
    return []


def module_record_options(record: Dict[str, Any]) -> Dict[str, Any]:
    raw = record.get("options")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def module_record_facets(record: Dict[str, Any]) -> Dict[str, str]:
    options = module_record_options(record)
    search = options.get("_search") if isinstance(options.get("_search"), dict) else {}
    path = str(record.get("path") or "")
    return {
        "platform": normalize_platform(search.get("platform") or options.get("platform") or record.get("platform")),
        "protocol": str(search.get("protocol") or options.get("protocol") or record.get("protocol") or infer_protocol_from_module_path(path)).lower(),
        "reliability": normalize_reliability(
            search.get("reliability") or options.get("reliability") or record.get("reliability") or record.get("severity")
        ),
    }


def module_record_timestamp(record: Dict[str, Any]) -> Optional[datetime]:
    for key in ("updated_at", "file_mtime", "created_at"):
        value = record.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, datetime):
            return value
        text = str(value).strip()
        if not text:
            continue
        parsed = parse_date(text)
        if parsed:
            return parsed
    return None


def query_tokens(query: str) -> List[str]:
    return [token.strip().lower() for token in str(query or "").replace(",", " ").split() if token.strip()]


def record_matches_query(record: Dict[str, Any], query: str) -> bool:
    tokens = query_tokens(query)
    if not tokens:
        return True
    tags = " ".join(module_record_tags(record))
    blob = " ".join(
        [
            str(record.get("name") or ""),
            str(record.get("description") or ""),
            str(record.get("path") or ""),
            tags,
            str(record.get("author") or ""),
            str(record.get("cve") or ""),
        ]
    ).lower()
    return all(token in blob for token in tokens)


def apply_module_search_filters(records: Iterable[Dict[str, Any]], filters: ModuleSearchFilters) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    normalized_type = filters.normalized_type()
    normalized_reliability = filters.normalized_reliability()

    for record in records or []:
        if not isinstance(record, dict):
            continue
        if filters.query and not record_matches_query(record, filters.query):
            continue

        record_type = str(record.get("type") or infer_module_type_from_path(str(record.get("path") or ""))).lower()
        if normalized_type and record_type != normalized_type:
            continue

        author = str(record.get("author") or "").lower()
        if filters.author and filters.author.lower() not in author:
            continue

        cve = str(record.get("cve") or "").lower()
        if filters.cve and filters.cve.lower() not in cve and filters.cve.lower() not in str(record.get("path") or "").lower():
            continue

        if filters.tag:
            tags = module_record_tags(record)
            if filters.tag.lower() not in tags and filters.tag.lower() not in " ".join(tags):
                continue

        facets = module_record_facets(record)
        path = str(record.get("path") or "").lower()
        tags = module_record_tags(record)

        if filters.platform:
            plat = filters.platform.lower()
            haystack = " ".join([facets.get("platform", ""), path] + tags).lower()
            if plat not in haystack:
                continue

        if filters.protocol:
            proto = filters.protocol.lower()
            protocol = facets.get("protocol") or infer_protocol_from_module_path(str(record.get("path") or ""))
            haystack = " ".join([protocol, path]).lower()
            if proto not in haystack:
                continue

        if normalized_reliability:
            reliability = facets.get("reliability") or ""
            if normalized_reliability != reliability:
                continue

        timestamp = module_record_timestamp(record)
        if filters.since and (not timestamp or timestamp < filters.since):
            continue
        if filters.until and (not timestamp or timestamp > filters.until):
            continue

        enriched = dict(record)
        enriched.setdefault("platform", facets.get("platform") or "")
        enriched.setdefault("protocol", facets.get("protocol") or infer_protocol_from_module_path(str(record.get("path") or "")))
        enriched.setdefault("reliability", facets.get("reliability") or "")
        results.append(enriched)
        if len(results) >= max(1, int(filters.limit or 50)):
            break

    return results
