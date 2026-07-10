#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Vulnerability-class specialist guidance for the planning LLM.

Generalized class expertise (not target-specific): when a vector is confirmed or
suspected, inject deep technique-tree hints so the agent exhausts bypass variants
instead of giving up after a naive attempt.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

SPECIALIST_HINTS: Dict[str, str] = {
    "lfi": (
        "LFI SPECIALIST: confirm primitive with benign canary (/etc/passwd, index.php) first. "
        "Exhaust traversal byte-forms: plain ../, collapse ....//, slash-mix ..\\/, "
        "url-enc %2e%2e%2f, double-enc, overlong, absolute prefix-break. "
        "Use php://filter/convert.base64-encode for source reads. "
        "Escalate via log poisoning (quote discipline), php://input, data://, session files. "
        "Judge hits by differential signal (length/hash delta), not brittle substring absence."
    ),
    "ssti": (
        "SSTI SPECIALIST: fingerprint engine with arithmetic probes ({{7*7}}, ${7*7}, #{7*7}). "
        "Bypass filters via bracket access obj['__class__'], attr() filter, concat splits. "
        "Enumerate __subclasses__() for gadgets; reach os via globals when request is blocked. "
        "For secrets objectives, pull config/SECRET_KEY via template context before attempting RCE."
    ),
    "sqli": (
        "SQLi SPECIALIST: confirm with boolean/time/error oracles before extraction. "
        "Try union, error-based, stacked, and blind techniques per DBMS fingerprint. "
        "Bypass WAF with encoding, comment injection, case variation, alternative operators. "
        "Chain to file read or command execution only when DBMS and privileges support it."
    ),
    "xss": (
        "XSS SPECIALIST: classify reflected/stored/DOM. Test context-aware payloads "
        "(attribute, script, event handler, SVG, template). "
        "Bypass filters with encoding, tag mutation, polyglot probes, and browser-hook validation "
        "for DOM sinks. Confirm execution, not just reflection."
    ),
    "ssrf": (
        "SSRF SPECIALIST: map URL/fetch parameters, test loopback and metadata endpoints "
        "(169.254.169.254, 127.0.0.1). Try protocol smuggling (file://, gopher://, dict://), "
        "DNS rebinding hints, and encoding bypasses when blocked."
    ),
    "auth": (
        "AUTH SPECIALIST: enumerate login surface, default creds, password spray with lockout "
        "awareness, session fixation, JWT alg=none/weak-secret, OAuth redirect abuse, "
        "and credential stuffing from OSINT persona when approved."
    ),
}

_PATH_CATEGORY_MAP: Dict[str, str] = {
    "lfi": "lfi",
    "path_traversal": "lfi",
    "file_inclusion": "lfi",
    "log_poison": "lfi",
    "ssti": "ssti",
    "template": "ssti",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "sqli_engine": "sqli",
    "xss": "xss",
    "dom_xss": "xss",
    "ssrf": "ssrf",
    "cloud_metadata": "ssrf",
    "login": "auth",
    "bruteforce": "auth",
    "credential": "auth",
    "jwt": "auth",
}


def _category_from_blob(blob: str) -> Optional[str]:
    low = str(blob or "").lower()
    for needle, category in _PATH_CATEGORY_MAP.items():
        if needle in low:
            return category
    return None


def specialist_for_path(path: str) -> Optional[str]:
    category = _category_from_blob(path)
    if category:
        return SPECIALIST_HINTS.get(category)
    return None


def specialist_for_finding(finding: Mapping[str, Any]) -> Optional[str]:
    if not isinstance(finding, Mapping):
        return None
    blob = " ".join([
        str(finding.get("path") or ""),
        str(finding.get("module") or ""),
        str(finding.get("message") or ""),
        " ".join(str(h) for h in (finding.get("context_hints") or [])),
    ])
    category = _category_from_blob(blob)
    if category:
        return SPECIALIST_HINTS.get(category)
    return None


def collect_specialist_hints(
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
    module_paths: Optional[Sequence[str]] = None,
    *,
    max_hints: int = 3,
) -> List[Dict[str, str]]:
    """Return deduplicated specialist hints for LLM context."""
    seen: set = set()
    hints: List[Dict[str, str]] = []

    for path in module_paths or []:
        text = specialist_for_path(str(path or ""))
        if text:
            key = _category_from_blob(str(path))
            if key and key not in seen:
                seen.add(key)
                hints.append({"category": key, "hint": text})

    for finding in findings or []:
        if not isinstance(finding, Mapping):
            continue
        text = specialist_for_finding(finding)
        if not text:
            continue
        key = _category_from_blob(
            str(finding.get("path") or "") + str(finding.get("message") or "")
        )
        if key and key not in seen:
            seen.add(key)
            hints.append({"category": key, "hint": text})
        if len(hints) >= max_hints:
            break

    return hints[:max_hints]
