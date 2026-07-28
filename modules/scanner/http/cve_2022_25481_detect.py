#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ThinkPHP 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ThinkPHP 5.0.24 - Information Disclosure Detection',
        'description': 'ThinkPHP 5.0.24 is susceptible to information disclosure. This version was configured without the PATHINFO parameter. This can allow an attacker to access all system environment parameters from index.php, thereby possibly obtaining sensitive information, modifying data, and/or executing unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'thinkphp', 'exposure', 'oss', 'vuln'],
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
            'https://github.com/Lyther/VulnDiscover/blob/master/Web/ThinkPHP_InfoLeak.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-25481',
            'https://github.com/20142995/sectool',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-25481',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?s=example', allow_redirects=False)
        if not r or r.status_code not in (200, 500, 404):
            return False
        body = r.text or ""
        body_all = ('Exception', 'REQUEST_TIME', 'ThinkPHP Constants',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="ThinkPHP 5.0.24 - Information Disclosure detected",
                path='/index.php?s=example',
            )
            return True
        return False

