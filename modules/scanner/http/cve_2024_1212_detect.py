#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Progress Kemp LoadMaster - Command Injection Detection',
        'description': 'Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'progress', 'rce', 'loadmaster', 'kev', 'vkev', 'vuln'],
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
            'https://rhinosecuritylabs.com/research/cve-2024-1212unauthenticated-command-injection-in-progress-kemp-loadmaster',
            'https://support.kemptechnologies.com/hc/en-us/articles/23878931058445-LoadMaster-Security-Vulnerability-CVE-2024-1212',
            'https://support.kemptechnologies.com/hc/en-us/articles/24325072850573-Release-Notice-LMOS-7-2-59-2-7-2-54-8-7-2-48-10-CVE-2024-1212',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-1212',
            'https://freeloadbalancer.com/',
        ],
        'cve': 'CVE-2024-1212',
    }

    def run(self):
        r = self.http_request(method="GET", path='/access/set?param=enableapi&value=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bin', 'mnt', 'WWW-Authenticate: Basic',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Progress Kemp LoadMaster - Command Injection detected",
                path='/access/set?param=enableapi&value=1',
            )
            return True
        return False

