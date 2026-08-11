#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Spring Boot Actuator endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import is_spa_catchall, validate_json_probe
from lib.scanner.http.response_validation import (
    is_html_response,
    looks_like_spring_actuator_env,
    looks_like_spring_actuator_health,
    looks_like_spring_actuator_links,
)


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
            ("/actuator", looks_like_spring_actuator_links, "info"),
            ("/actuator/health", looks_like_spring_actuator_health, "info"),
            ("/actuator/env", looks_like_spring_actuator_env, "high"),
        ]
        for path, validator, severity in probes:
            data, response = validate_json_probe(self.http_request, path, validator)
            if data:
                self.set_info(severity=severity, reason=f"Spring Boot Actuator exposed at {path}", path=path)
                return True

        r = self.http_request(method="GET", path="/actuator/heapdump", allow_redirects=False)
        home = self.http_request(method="GET", path="/", allow_redirects=False)
        if r and home and int(r.status_code or 0) == 200 and not is_html_response(r):
            if not is_spa_catchall(r, home):
                content = r.content or b""
                if len(content) > 1024 and content[:2] == b"PK":
                    self.set_info(severity="critical", reason="Spring Actuator heapdump exposed", path="/actuator/heapdump")
                    return True
        return False
