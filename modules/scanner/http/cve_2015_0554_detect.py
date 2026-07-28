#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ADB (formerly Pirelli Broadband Solutions) P."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ADB/Pirelli ADSL2/2+ Wireless Router P.DGA4001N - Information Disclosure Detection',
        'description': 'ADB (formerly Pirelli Broadband Solutions) P.DGA4001N router with firmware PDG_TEF_SP_4.06L.6 does not properly restrict access to the web interface, which allows remote attackers to obtain sensitive information or cause a denial of service (device restart) as demonstrated by a direct request to (1) wlsecurity.html or (2) resetrouter.html.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'pirelli', 'router', 'disclosure', 'edb', 'packetstorm', 'adb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/35721',
            'http://packetstormsecurity.com/files/129828/Pirelli-ADSL2-2-Wireless-Router-P.DGA4001N-Information-Disclosure.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-0554',
            'http://www.exploit-db.com/exploits/35721',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2015-0554',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wlsecurity.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('var wpapskkey', 'var WscDevPin', 'var sessionkey',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="ADB/Pirelli ADSL2/2+ Wireless Router P.DGA4001N - Information Disclosure detected",
                path='/wlsecurity.html',
            )
            return True
        return False

