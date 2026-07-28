#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpinfo() is susceptible to resource exposure in unprotected composer vendor folders via phpfastcache/phpfastc."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpfastcache - phpinfo Resource Exposure Detection',
        'description': 'phpinfo() is susceptible to resource exposure in unprotected composer vendor folders via phpfastcache/phpfastcache.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'exposure', 'phpfastcache', 'phpinfo', 'phpsocialnetwork', 'vuln'],
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
            'https://github.com/PHPSocialNetwork/phpfastcache/pull/813',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37704',
            'https://github.com/PHPSocialNetwork/phpfastcache/security/advisories/GHSA-cvh5-p6r6-g2qc',
            'https://packagist.org/packages/phpfastcache/phpfastcache',
            'https://github.com/PHPSocialNetwork/phpfastcache/blob/master/CHANGELOG.md#807',
        ],
        'cve': 'CVE-2021-37704',
    }

    def run(self):
        for path in ('/vendor/phpfastcache/phpfastcache/docs/examples/phpinfo.php', '/vendor/phpfastcache/phpfastcache/examples/phpinfo.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('PHP Extension', 'PHP Version',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="phpfastcache - phpinfo Resource Exposure detected",
                    path=path,
                )
                return True
        return False

