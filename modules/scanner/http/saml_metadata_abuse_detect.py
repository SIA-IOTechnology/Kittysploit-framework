#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed SAML metadata and weak signing configuration."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.saml_metadata_probe import scan_saml_metadata


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SAML Metadata Exposure & Misconfiguration Detection",
        "description": (
            "Probes common SAML metadata paths for exposed EntityDescriptor XML, "
            "unsigned assertions, and embedded X509 certificates."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "saml", "sso", "metadata", "misconfig", "auth"],
        "modules": ["scanner/http/simplesamlphp_detect"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 9,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 0.8,
            "noise": 0.3,
            "value": 1.0,
        },
    }

    def run(self):
        findings = scan_saml_metadata(self.http_request)
        if not findings:
            return False

        high = [f for f in findings if f.get("severity") in ("critical", "high")]
        entities = sorted({str(f.get("entity_id") or "") for f in findings if f.get("entity_id")})

        self.set_info(
            severity="high" if high else "medium",
            reason=f"SAML metadata exposed ({len(findings)} issue(s), {len(entities)} entity/entities)",
            path=findings[0].get("path") or "/metadata",
            findings=findings[:15],
            entity_ids=entities[:5],
        )
        return True
