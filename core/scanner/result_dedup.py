#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deduplicate and group KittySploit scanner findings by host, service and evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

SEVERITY_RANK = {
    "critical": 5,
    "crit": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "unknown": 0,
}

PORT_PROTOCOL = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http",
    8443: "https",
}


@dataclass
class ScannerFindingGroup:
    """Aggregated scanner finding spanning one or more detections."""

    vulnerability_key: str
    title: str
    severity: str
    cve: str = ""
    hosts: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    module_paths: List[str] = field(default_factory=list)
    occurrences: int = 0
    representative: Dict[str, Any] = field(default_factory=dict)
    members: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_key": self.vulnerability_key,
            "title": self.title,
            "severity": self.severity,
            "cve": self.cve,
            "hosts": list(self.hosts),
            "services": list(self.services),
            "evidence": list(self.evidence),
            "modules": list(self.modules),
            "module_paths": list(self.module_paths),
            "occurrences": self.occurrences,
            "representative": dict(self.representative),
            "members": list(self.members),
        }


def enrich_scanner_result(result: Dict[str, Any], target_info: Optional[Dict[str, Any]] = None, *, port: Optional[int] = None) -> Dict[str, Any]:
    """Attach host/service/url/evidence fields used for deduplication."""
    enriched = dict(result or {})
    target = target_info or {}

    host = str(enriched.get("host") or target.get("hostname") or "").strip()
    chosen_port = enriched.get("port")
    if chosen_port in (None, ""):
        chosen_port = port if port is not None else target.get("port")
    try:
        chosen_port = int(chosen_port) if chosen_port not in (None, "") else None
    except (TypeError, ValueError):
        chosen_port = None

    scheme = str(enriched.get("scheme") or target.get("scheme") or "").strip().lower()
    protocol = infer_protocol_from_result(enriched, chosen_port, scheme)
    service = format_service(protocol, chosen_port)

    if host:
        enriched["host"] = host
    if chosen_port is not None:
        enriched["port"] = chosen_port
    if protocol:
        enriched["protocol"] = protocol
    if service:
        enriched["service"] = service
    if not enriched.get("url") and host and chosen_port is not None:
        enriched["url"] = target.get("url") or f"{scheme or protocol}://{host}:{chosen_port}/"
    if not enriched.get("cve"):
        enriched["cve"] = extract_cve(enriched)
    enriched["evidence"] = extract_evidence(enriched)
    enriched["vulnerability_key"] = vulnerability_key(enriched)
    return suppress_noise_finding(suppress_speculative_finding(enriched))


_INFO_SEVERITIES = frozenset({"info", "informational"})

_NOISE_PATH_MARKERS = (
    "server_banner",
    "waf_fingerprint",
    "robots_txt",
    "grpc_reflection_detect",
)


def suppress_noise_finding(result: Dict[str, Any]) -> Dict[str, Any]:
    """Drop info-level technology fingerprints that are not actionable vulnerabilities."""
    item = dict(result or {})
    if not item.get("vulnerable"):
        return item

    path = str(item.get("path") or "").lower()
    severity = str(item.get("severity") or "").lower()
    message = str(item.get("message") or "").lower()

    if "grpc_reflection_detect" in path and (
        "reflection not confirmed" in message or "heuristic" in message
    ):
        item["vulnerable"] = False
        item["status"] = "safe"
        item["suppressed_reason"] = "suppressed inconclusive gRPC reflection probe"
        return item

    if severity not in _INFO_SEVERITIES:
        return item

    if any(marker in path for marker in _NOISE_PATH_MARKERS):
        item["vulnerable"] = False
        item["status"] = "safe"
        item["suppressed_reason"] = "suppressed info-level technology detection"
        return item

    try:
        from interfaces.command_system.builtin.agent.agent_constants import (
            PURE_DETECTION_PATH_MARKERS,
            STRONG_VULN_SIGNAL_PHRASES,
        )
    except ImportError:
        return item

    if any(marker in path for marker in PURE_DETECTION_PATH_MARKERS):
        if not any(phrase in message for phrase in STRONG_VULN_SIGNAL_PHRASES):
            item["vulnerable"] = False
            item["status"] = "safe"
            item["suppressed_reason"] = "suppressed pure detection (info)"
    return item


def suppress_speculative_finding(result: Dict[str, Any]) -> Dict[str, Any]:
    """Drop CVE rows that only have weak/indirect evidence (common on SPA catch-all hosts)."""
    item = dict(result or {})
    if not item.get("vulnerable"):
        return item
    if not extract_cve(item):
        return item

    details = item.get("details") or {}
    confidence = str(
        details.get("confidence")
        or item.get("confidence")
        or ""
    ).strip().lower()

    if confidence in {"high", "confirmed", "critical"}:
        return item

    message = str(item.get("message") or "").lower()
    speculative_phrases = (
        "potentially vulnerable",
        "version unknown",
        "json parsing failed",
        "unparseable",
        "inconclusive",
        "likely vulnerable",
        "expected vulnerable range",
        "active probes disabled",
    )
    if confidence in {"low", "medium", "unknown", ""} or any(p in message for p in speculative_phrases):
        item["vulnerable"] = False
        item["status"] = "safe"
        item["suppressed_reason"] = (
            f"suppressed speculative CVE finding (confidence={confidence or 'unknown'})"
        )
    return item


def deduplicate_scanner_results(
    results: Sequence[Dict[str, Any]],
    *,
    target_info: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Collapse duplicate scanner findings that share host, service, vulnerability and evidence.

    Keeps the highest-severity representative and annotates merged rows with ``duplicate_count``.
    """
    grouped: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    order: List[Tuple[str, ...]] = []

    for raw in results or []:
        if not isinstance(raw, dict):
            continue
        item = enrich_scanner_result(raw, target_info, port=raw.get("port"))
        if not item.get("vulnerable"):
            grouped_key = ("__non_vulnerable__", id(item))
            grouped[grouped_key] = item
            order.append(grouped_key)
            continue

        key = dedup_key(item)
        if key not in grouped:
            copy = dict(item)
            copy["duplicate_count"] = 1
            copy["dedup_sources"] = [item.get("path") or item.get("module") or ""]
            grouped[key] = copy
            order.append(key)
            continue

        existing = grouped[key]
        existing["duplicate_count"] = int(existing.get("duplicate_count") or 1) + 1
        sources = list(existing.get("dedup_sources") or [])
        source = item.get("path") or item.get("module") or ""
        if source and source not in sources:
            sources.append(source)
        existing["dedup_sources"] = sources
        if severity_rank(item.get("severity")) > severity_rank(existing.get("severity")):
            preserved = {
                "duplicate_count": existing["duplicate_count"],
                "dedup_sources": existing["dedup_sources"],
            }
            existing.clear()
            existing.update(item)
            existing.update(preserved)

    return [grouped[key] for key in order if key in grouped]


def group_scanner_results(
    results: Sequence[Dict[str, Any]],
    *,
    target_info: Optional[Dict[str, Any]] = None,
) -> List[ScannerFindingGroup]:
    """Group deduplicated vulnerabilities by shared vulnerability identity."""
    deduped = deduplicate_scanner_results(results, target_info=target_info)
    buckets: Dict[str, ScannerFindingGroup] = {}
    order: List[str] = []

    for item in deduped:
        if not item.get("vulnerable"):
            continue
        key = str(item.get("vulnerability_key") or vulnerability_key(item))
        if key not in buckets:
            buckets[key] = ScannerFindingGroup(
                vulnerability_key=key,
                title=str(item.get("module") or item.get("path") or key),
                severity=str(item.get("severity") or "unknown"),
                cve=str(item.get("cve") or ""),
                representative=dict(item),
                members=[dict(item)],
                occurrences=int(item.get("duplicate_count") or 1),
            )
            order.append(key)
        else:
            group = buckets[key]
            group.members.append(dict(item))
            group.occurrences += int(item.get("duplicate_count") or 1)
            if severity_rank(item.get("severity")) > severity_rank(group.severity):
                group.severity = str(item.get("severity") or group.severity)
                group.representative = dict(item)
            if not group.cve and item.get("cve"):
                group.cve = str(item.get("cve"))

        group = buckets[key]
        _append_unique(group.hosts, item.get("host"))
        _append_unique(group.services, item.get("service"))
        _append_unique(group.evidence, item.get("evidence"))
        _append_unique(group.modules, item.get("module"))
        _append_unique(group.module_paths, item.get("path"))

    groups = [buckets[key] for key in order]
    groups.sort(key=lambda g: (-severity_rank(g.severity), -g.occurrences, g.title.lower()))
    return groups


def dedup_key(result: Dict[str, Any]) -> Tuple[str, ...]:
    return (
        str(result.get("vulnerability_key") or vulnerability_key(result)),
        str(result.get("host") or "").lower(),
        str(result.get("service") or "").lower(),
        normalize_text(result.get("evidence") or "")[:200],
    )


def vulnerability_key(result: Dict[str, Any]) -> str:
    cve = extract_cve(result)
    if cve:
        return f"cve:{cve.lower()}"
    path = str(result.get("path") or "").strip().lower()
    message = normalize_text(result.get("message") or "")
    if message:
        return f"finding:{path}:{message[:120]}"
    module = str(result.get("module") or path or "unknown").strip().lower()
    return f"module:{module}"


def extract_cve(result: Dict[str, Any]) -> str:
    raw = result.get("cve")
    if isinstance(raw, (list, tuple)):
        for item in raw:
            value = str(item or "").strip().upper()
            if CVE_RE.match(value):
                return value
        return ""
    value = str(raw or "").strip().upper()
    if CVE_RE.match(value):
        return value

    details = result.get("details") or {}
    if isinstance(details, dict):
        detail_cve = details.get("cve")
        if isinstance(detail_cve, (list, tuple)):
            for item in detail_cve:
                value = str(item or "").strip().upper()
                if CVE_RE.match(value):
                    return value
        else:
            value = str(detail_cve or "").strip().upper()
            if CVE_RE.match(value):
                return value

    path = str(result.get("path") or "")
    match = re.search(r"cve[_-]?(\d{4})[_-]?(\d{4,})", path, re.IGNORECASE)
    if match:
        return f"CVE-{match.group(1)}-{match.group(2)}".upper()
    return ""


def extract_evidence(result: Dict[str, Any]) -> str:
    parts: List[str] = []
    message = str(result.get("message") or "").strip()
    module_description = str(result.get("module_description") or "").strip()
    details = result.get("details") or {}
    detail_reason = ""
    if isinstance(details, dict):
        detail_reason = str(details.get("reason") or "").strip()

    finding = detail_reason or message
    if finding and not _is_generic_module_description(finding, module_description):
        parts.append(finding)

    if isinstance(details, dict):
        for key in ("action", "confidence", "path", "url", "parameter", "probe"):
            value = details.get(key)
            if value in (None, ""):
                continue
            parts.append(f"{key}={value}")

    version = result.get("version")
    if version:
        parts.append(f"version={version}")

    if not parts and finding:
        parts.append(finding)
    elif not parts and message:
        parts.append(message)

    return normalize_text(" | ".join(parts))[:400]


def _is_generic_module_description(text: str, module_description: str = "") -> bool:
    """True when *text* is only the static module blurb, not a concrete finding."""
    norm = normalize_text(text)
    if not norm:
        return True
    if module_description and norm == normalize_text(module_description):
        return True
    generic_prefixes = (
        "detects if ",
        "detects ",
        "connects to a ",
        "connects to ",
    )
    return any(norm.startswith(prefix) for prefix in generic_prefixes)


def reason_redundant_with_evidence(reason: str, evidence: str) -> bool:
    """Return True when a separate Reason line would repeat Evidence."""
    r = normalize_text(reason)
    e = normalize_text(evidence)
    if not r:
        return True
    if not e:
        return False
    if r == e:
        return True
    if r in e or e in r:
        return True
    if e.startswith(r + " |") or e.startswith(r + "|"):
        return True
    return False


def infer_protocol_from_result(result: Dict[str, Any], port: Optional[int], scheme: str = "") -> str:
    path = str(result.get("path") or "").lower()
    if path.startswith("scanner/http/") or "/http/" in path:
        if port == 443 or scheme == "https":
            return "https"
        return "http"
    if path.startswith("scanner/cloud/"):
        return "cloud"
    if path.startswith("scanner/ldap/"):
        return "ldap"
    if path.startswith("scanner/telecom/"):
        return "telecom"
    if path.startswith("scanner/redis/"):
        return "redis"
    if path.startswith("scanner/mysql/"):
        return "mysql"
    if path.startswith("scanner/smb/"):
        return "smb"
    if path.startswith("scanner/ftp/"):
        return "ftp"
    if path.startswith("scanner/ssh/"):
        return "ssh"
    if port is not None and port in PORT_PROTOCOL:
        return PORT_PROTOCOL[port]
    if scheme in ("http", "https"):
        return scheme
    return "tcp"


def format_service(protocol: str, port: Optional[int]) -> str:
    if port is None:
        return protocol or "unknown"
    return f"{protocol}:{port}" if protocol else str(port)


def severity_rank(severity: Any) -> int:
    return SEVERITY_RANK.get(str(severity or "").strip().lower(), 0)


def normalize_text(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _append_unique(values: List[str], value: Any):
    text = str(value or "").strip()
    if text and text not in values:
        values.append(text)
