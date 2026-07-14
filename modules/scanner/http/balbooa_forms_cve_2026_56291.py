#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import BAFORMS_PATCHED_VERSION, Joomla


class Module(Scanner, Http_client, Joomla):
    __info__ = {
        "name": "Balbooa Forms CVE-2026-56291 detection",
        "description": (
            "Detects Joomla sites running Balbooa Forms (com_baforms) < 2.4.1 vulnerable to "
            "CVE-2026-56291 — unauthenticated arbitrary file upload via "
            "form.uploadAttachmentFile without CSRF or permission checks."
        ),
        "author": ["Phil Taylor", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-56291",
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-56291",
        ],
        "modules": [
            "exploits/multi/http/balbooa_forms_cve_2026_56291_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "joomla",
            "balbooa",
            "baforms",
            "file-upload",
            "rce",
            "unauthenticated",
            "cve-2026-56291",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["joomla", "php"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {"joomla": 0.3, "php": 0.3},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_upload", "from_detail": ""},
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def run(self):
        joomla = self.probe_joomla()
        if not joomla.get("found"):
            return False

        baforms = self.probe_baforms()
        if not baforms.get("found"):
            return False

        version = baforms.get("version")
        evidence = baforms.get("evidence") or "com_baforms"
        joomla_version = joomla.get("version") or "unknown"

        if version and self.baforms_is_patched(version):
            self.set_info(
                severity="info",
                reason=(
                    f"Balbooa Forms {version} detected at {evidence}; "
                    f">= {BAFORMS_PATCHED_VERSION} (patched)"
                ),
                service="joomla",
                joomla_version=joomla_version,
                baforms_version=version,
            )
            return False

        confidence = "high" if version else "medium"
        version_text = version or "unknown"
        reason = (
            f"Joomla {joomla_version} with Balbooa Forms {version_text} at {evidence}; "
            f"< {BAFORMS_PATCHED_VERSION} is affected by CVE-2026-56291 "
            "(unauthenticated PHP upload via form.uploadAttachmentFile)"
        )
        self.set_info(
            severity="critical",
            cve="CVE-2026-56291",
            reason=reason,
            service="joomla",
            endpoint="/index.php?option=com_baforms&task=form.uploadAttachmentFile",
            joomla_version=joomla_version,
            baforms_version=version_text,
            confidence=confidence,
        )
        return True
