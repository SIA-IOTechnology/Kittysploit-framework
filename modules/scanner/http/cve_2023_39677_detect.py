#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PrestaShop modules by MyPrestaModules expose PHPInfo."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PrestaShop MyPrestaModules - PhpInfo Disclosure Detection',
        'description': 'PrestaShop modules by MyPrestaModules expose PHPInfo',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'prestashop', 'phpinfo', 'disclosure', 'simpleimportproduct_project', 'vuln'],
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
            'https://blog.sorcery.ie/posts/myprestamodules_phpinfo/',
            'https://cve.report/CVE-2023-39677',
            'https://myprestamodules.com/',
            'https://sorcery.ie',
        ],
        'cve': 'CVE-2023-39677',
    }

    def run(self):
        for path in ('/modules/simpleimportproduct/send.php?phpinfo=1', '/modules/updateproducts/send.php?phpinfo=1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('PHP Extension', 'PHP Version',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="PrestaShop MyPrestaModules - PhpInfo Disclosure detected",
                    path=path,
                )
                return True
        return False

