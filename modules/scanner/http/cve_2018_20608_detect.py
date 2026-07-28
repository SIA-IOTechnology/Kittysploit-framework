#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Imcat 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Imcat 4.4 - Phpinfo Configuration Detection',
        'description': 'Imcat 4.4 allows remote attackers to read phpinfo output via the root/tools/adbug/binfo.php?phpinfo1 URI.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'imcat', 'phpinfo', 'config', 'txjia', 'vuln'],
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2018-20608', 'https://github.com/SexyBeast233/SecBooks'],
        'cve': 'CVE-2018-20608',
    }

    def run(self):
        r = self.http_request(method="GET", path='/imcat/root/tools/adbug/binfo.php?phpinfo1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PHP Extension', 'PHP Version',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Imcat 4.4 - Phpinfo Configuration detected",
                path='/imcat/root/tools/adbug/binfo.php?phpinfo1',
            )
            return True
        return False

