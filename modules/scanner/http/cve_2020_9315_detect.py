#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle iPlanet Web Server 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle iPlanet Web Server 7.0.x - Authentication Bypass Detection',
        'description': 'Oracle iPlanet Web Server 7.0.x has incorrect access control for admingui/version URIs in the Administration console, as demonstrated by unauthenticated read access to encryption keys. NOTE a related support policy can be found in the www.oracle.com references attached to this CVE.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'oracle', 'auth-bypass', 'iplanet', 'vuln'],
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
            'https://www.cvebase.com/cve/2020/9315',
            'https://www.oracle.com/support/lifetime-support/',
            'https://www.oracle.com/us/assets/lifetime-support-middleware-069163.pdf',
            'https://wwws.nightwatchcybersecurity.com/2020/05/10/two-vulnerabilities-in-oracles-iplanet-web-server-cve-2020-9315-and-cve-2020-9314/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-9315',
        ],
        'cve': 'CVE-2020-9315',
    }

    def run(self):
        for path in ('/admingui/version/serverTasksGeneral?serverTasksGeneral.GeneralWebserverTabs.TabHref=2', '/admingui/version/serverConfigurationsGeneral?serverConfigurationsGeneral.GeneralWebserverTabs.TabHref=4'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Admin Console', 'serverConfigurationsGeneral', 'serverCertificatesGeneral',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Oracle iPlanet Web Server 7.0.x - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

