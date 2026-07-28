#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pyLoad is the free and open-source Download Manager written in pure Python."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'pyLoad Flask Config - Access Control Detection',
        'description': 'pyLoad is the free and open-source Download Manager written in pure Python. Any unauthenticated user can browse to a specific URL to expose the Flask config, including the `SECRET_KEY` variable. This issue has been patched in version 0.5.0b3.dev77.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'python', 'pip', 'pyload', 'access-control', 'vuln'],
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
            'https://github.com/advisories/GHSA-mqpq-2p68-46fv',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-21644',
            'https://github.com/ltranquility/CVE-2024-21644-Poc',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2024-21644',
    }

    def run(self):
        r = self.http_request(method="GET", path='/render/info.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('&#39;SECRET_KEY&#39;:', '&#39;pyload_session&#39;',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="pyLoad Flask Config - Access Control detected",
                path='/render/info.html',
            )
            return True
        return False

