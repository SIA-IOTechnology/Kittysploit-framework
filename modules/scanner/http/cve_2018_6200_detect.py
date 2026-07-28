#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBulletin 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin - Open Redirect Detection',
        'description': 'vBulletin 3.x.x and 4.2.x through 4.2.5 contains an open redirect vulnerability via the redirector.php URL parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'redirect', 'vbulletin', 'vuln'],
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
            'https://cxsecurity.com/issue/WLB-2018010251',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-6200',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-6200',
    }

    def run(self):
        for path in ('/redirector.php?url=https://interact.sh', '/redirector.php?do=nodelay&url=https://interact.sh'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<meta http-equiv="refresh" content="0; URL=https://interact.sh">',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="vBulletin - Open Redirect detected",
                    path=path,
                )
                return True
        return False

