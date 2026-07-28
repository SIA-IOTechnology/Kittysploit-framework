#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Boa 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Boa 0.94.13 - Information Disclosure Detection',
        'description': 'Boa 0.94.13 allows remote attackers to obtain sensitive information via a misconfiguration involving backup.html, preview.html, js/log.js, log.html, email.html, online-users.html, and config.js. NOTE- multiple third parties report that this is a site-specific issue because those files are not part of Boa.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'boa', 'info-leak', 'vkev', 'vuln'],
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
            'https://sourceforge.net/projects/boa/files/boa/0.94.13/',
            'https://github.com/anldori/CVE-2021-33558',
        ],
        'cve': 'CVE-2021-33558',
    }

    def run(self):
        r = self.http_request(method="GET", path='/js/log.js', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('function searchlog', 'logtime',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Boa 0.94.13 - Information Disclosure detected",
                path='/js/log.js',
            )
            return True
        return False

