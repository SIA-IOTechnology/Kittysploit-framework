#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Spring Boot Actuator endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Spring Boot Actuator Detection",
        "description": "Detects exposed Spring Boot Actuator health, env, and heapdump endpoints.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://docs.spring.io/spring-boot/reference/actuator/endpoints.html"],
        "tags": ["web", "scanner", "spring", "actuator", "misconfig", "java"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 4,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
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
        'chain':         {'produces_capabilities': [{'capability': 'devops_panel', 'from_detail': ''},
                                   {'capability': 'misconfig_surface', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['auxiliary/scanner/http/debug_info_leak',
                                 'scanner/cloud/kubernetes_api_detect']},
    },
    }

    def run(self):
        probes = [
            ("/actuator", ["_links", "actuator"], "info"),
            ("/actuator/health", ['"status"', "UP", "DOWN"], "info"),
            ("/actuator/env", ["propertySources", "systemProperties"], "high"),
            ("/actuator/heapdump", [], "critical"),
        ]
        for path, markers, severity in probes:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401, 403):
                continue
            body = (r.text or "").lower()
            if path.endswith("heapdump") and r.status_code == 200 and len(r.content or b"") > 1024:
                self.set_info(severity="critical", reason="Spring Actuator heapdump exposed", path=path)
                return True
            if any(marker.lower() in body for marker in markers):
                self.set_info(severity=severity, reason=f"Spring Boot Actuator exposed at {path}", path=path)
                return True
        return False
