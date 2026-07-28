#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel ATP200, ATP500, ATP800, USG20-VPN, USG20W-VPN, USG40, USG40W, USG60, USG60W, USG110, USG210, USG310, USG."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel - Cross-Site Scripting Detection',
        'description': 'Zyxel ATP200, ATP500, ATP800, USG20-VPN, USG20W-VPN, USG40, USG40W, USG60, USG60W, USG110, USG210, USG310, USG1100, USG1900, USG2200-VPN, ZyWALL 110, ZyWALL 310, and ZyWALL 1100 devices contain a reflected cross-site scripting vulnerability on the security firewall login page via the mp_idx parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'zyxel', 'packetstorm', 'seclists', 'edb', 'xss', 'vuln'],
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
            'http://packetstormsecurity.com/files/152525/Zyxel-ZyWall-Cross-Site-Scripting.html',
            'https://www.exploit-db.com/exploits/46706/',
            'https://www.securitymetrics.com/blog/Zyxel-Devices-Vulnerable-Cross-Site-Scripting-Login-page',
            'https://www.zyxel.com/support/reflected-cross-site-scripting-vulnerability-of-firewalls.shtml',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-9955',
        ],
        'cve': 'CVE-2019-9955',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?mp_idx=%22;alert(%271%27);//', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('";alert(\'1\');//', '<title>Welcome</title>',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Zyxel - Cross-Site Scripting detected",
                path='/?mp_idx=%22;alert(%271%27);//',
            )
            return True
        return False

