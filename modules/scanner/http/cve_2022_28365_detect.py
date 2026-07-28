#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reprise License Manager 14."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Reprise License Manager 14.2 - Information Disclosure Detection',
        'description': 'Reprise License Manager 14.2 is susceptible to information disclosure via a GET request to /goforms/rlminfo. No authentication is required. The information disclosed is associated with software versions, process IDs, network configuration, hostname(s), system architecture and file/directory information. An attacker can possibly obtain further sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'rlm', 'packetstorm', 'exposure', 'reprisesoftware', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://www.reprisesoftware.com/products/software-license-management.php',
            'https://github.com/advisories/GHSA-4g2v-6x25-vr7p',
            'http://packetstormsecurity.com/files/166647/Reprise-License-Manager-14.2-Cross-Site-Scripting-Information-Disclosure.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-28365',
            'https://www.reprisesoftware.com/RELEASE_NOTES',
        ],
        'cve': 'CVE-2022-28365',
    }

    def run(self):
        r = self.http_request(method="GET", path='/goforms/rlminfo', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('RLM Version', 'Platform type',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Reprise License Manager 14.2 - Information Disclosure detected",
                path='/goforms/rlminfo',
            )
            return True
        return False

