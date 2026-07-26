#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Spring4Shell (CVE-2022-22965) parameter binding indicators."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Spring4Shell Detection",
        "description": (
            "Probes Spring Framework class.module.classLoader parameter binding "
            "behavior indicative of CVE-2022-22965 (safe fingerprint, no RCE)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2022-22965",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
        ],
        "tags": ["web", "scanner", "spring", "spring4shell", "cve", "java"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': True,
        'produces': ['tech_hints', 'risk_signals'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'java_vuln_signal', 'from_detail': ''},
                                   {'capability': 'cve_indicator', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['scanner/http/spring_actuator_detect',
                                 'auxiliary/scanner/http/java_deserialization']},
    },
    }

    def run(self):
        baseline = self.http_request(method="GET", path="/", allow_redirects=False)
        if not baseline:
            return False

        probe_path = (
            "/?class.module.classLoader.resources.context.parent.pipeline."
            "first.pattern=test&class.module.classLoader.resources.context."
            "parent.pipeline.first.suffix=.jsp"
        )
        probe = self.http_request(method="GET", path=probe_path, allow_redirects=False)
        if not probe:
            return False

        body = (probe.text or "").lower()
        indicators = (
            "classloader",
            "springframework",
            "invalid property",
            "bindexception",
            "method property",
            "access is denied",
        )
        if probe.status_code in (400, 500) and any(token in body for token in indicators):
            self.set_info(
                severity="high",
                reason="Spring classLoader parameter binding anomaly detected",
                cve="CVE-2022-22965",
            )
            return True

        if probe.status_code == 200 and baseline.status_code == 200 and probe.text != baseline.text:
            if "spring" in body or "whitelabel" in body:
                self.set_info(
                    severity="medium",
                    reason="Spring endpoint accepts class.module.classLoader parameters",
                    cve="CVE-2022-22965",
                )
                return True
        return False
