#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Boot Actuator SBOM endpoint was detected and is exposed without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Boot Actuator SBOM - Exposure Detection',
        'description': 'Spring Boot Actuator SBOM endpoint was detected and is exposed without authentication. The endpoint returns a Software Bill of Materials (typically CycloneDX or SPDX JSON) listing every dependency and version shipped with the application, which lets an attacker enumerate the exact library inventory and trivially map it to known CVEs for targeted exploitation.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'exposure', 'springboot', 'actuator', 'sbom'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://docs.spring.io/spring-boot/api/rest/actuator/sbom.html',
            'https://docs.spring.io/spring-boot/reference/actuator/endpoints.html#actuator.endpoints.sbom',
            'https://cyclonedx.org/specification/overview/',
            'https://spdx.github.io/spdx-spec/',
        ],
    }

    def run(self):
        return False  # disabled: corrupted matchers
        for path in ('/sbom', '/actuator/sbom', '/sbom/application', '/actuator/sbom/application'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ()
            header_any = ('application/json', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v3+json', 'application/vnd.cyclonedx+json', 'application/spdx+json', 'application/vnd.syft+json',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='low',
                    reason="Spring Boot Actuator SBOM - Exposure detected",
                    path=path,
                )
                return True
        return False

