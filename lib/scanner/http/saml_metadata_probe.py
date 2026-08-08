#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAML metadata exposure and misconfiguration probes."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

_SAML_PATHS = (
    "/metadata",
    "/saml/metadata",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/simplesaml/saml2/idp/metadata.php",
    "/auth/saml/metadata",
    "/saml2/metadata",
    "/sso/saml/metadata",
    "/.well-known/saml-metadata",
)

_WEAK_MARKERS = (
    ("WantAssertionsSigned=\"false\"", "assertions_not_required_signed", "high"),
    ("AuthnRequestsSigned=\"false\"", "authn_requests_unsigned", "medium"),
    ("<md:AssertionConsumerService", "acs_endpoint_exposed", "info"),
    ("<X509Certificate>", "x509_certificate_in_metadata", "medium"),
    ("entityID=", "entity_id_exposed", "info"),
)


def scan_saml_metadata_text(path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    body = text or ""
    if not body.strip():
        return findings
    lowered = body.lower()
    if not any(m in lowered for m in ("entitydescriptor", "saml", "fed:entity", "md:")):
        return findings
    entity_match = re.search(r'entityID=["\']([^"\']+)["\']', body, re.I)
    entity_id = entity_match.group(1) if entity_match else ""
    for marker, kind, severity in _WEAK_MARKERS:
        if marker.lower() in lowered.replace(" ", ""):
            findings.append(
                {
                    "path": path,
                    "kind": kind,
                    "severity": severity,
                    "entity_id": entity_id,
                }
            )
    if entity_id and not findings:
        findings.append(
            {
                "path": path,
                "kind": "saml_metadata_exposed",
                "severity": "medium",
                "entity_id": entity_id,
            }
        )
    return findings


def collect_saml_metadata(http_request: Callable[..., Any]) -> List[Tuple[str, str]]:
    bodies: List[Tuple[str, str]] = []
    for path in _SAML_PATHS:
        response = http_request(method="GET", path=path, allow_redirects=False)
        if not response:
            continue
        status = int(getattr(response, "status_code", 0) or 0)
        if status not in (200, 403):
            continue
        text = str(getattr(response, "text", "") or "")
        ctype = str((getattr(response, "headers", None) or {}).get("Content-Type") or "").lower()
        if "xml" in ctype or "saml" in text.lower()[:500]:
            bodies.append((path, text))
    return bodies


def scan_saml_metadata(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path, text in collect_saml_metadata(http_request):
        findings.extend(scan_saml_metadata_text(path, text))
    return findings


__all__ = ["scan_saml_metadata", "scan_saml_metadata_text", "collect_saml_metadata"]
