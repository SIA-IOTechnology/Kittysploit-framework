#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GLPI 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GLPI 9.2/<9.5.6 - Information Disclosure Detection',
        'description': 'GLPI 9.2 and prior to 9.5.6 is susceptible to information disclosure via the telemetry endpoint, which discloses GLPI and server information. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'glpi', 'exposure', 'glpi-project', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/glpi-project/glpi/security/advisories/GHSA-xx66-v3g5-w825',
            'https://github.com/glpi-project/glpi/releases/tag/9.5.6',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-39211',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2021-39211',
    }

    def run(self):
        for path in ('/ajax/telemetry.php', '/glpi/ajax/telemetry.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('"uuid":', '"glpi":',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="GLPI 9.2/<9.5.6 - Information Disclosure detected",
                    path=path,
                )
                return True
        return False

