#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple Firewall Devices from vendor Ruijie Networks are affected by an information leakage vulnerability whe."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RG-UAC Ruijie - Password Hashes Leak Detection',
        'description': 'Multiple Firewall Devices from vendor Ruijie Networks are affected by an information leakage vulnerability where credentials are included in the source code of the web admin login interface (usernames, roles, MD5 hashes and additional details of each user). Attackers can use this information to illegally access into the vulnerable devices, obtain sensitive device information and change configurations. The vulnerability is identified by CNVD-2021-14536.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'password', 'leak', 'ruijie', 'exposure', 'firewall', 'router', 'vuln'],
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
            'https://forum.butian.net/share/177',
            'https://www.ruijie.com.cn/gy/xw-aqtg-zw/86924/',
            'https://www.cnvd.org.cn/flaw/show/CNVD-2021-14536',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('\\"role\\":\\"super_admin\\"', '\\"role\\":\\"guest_admin\\"', '\\"role\\":\\"reporter_admin\\"',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="RG-UAC Ruijie - Password Hashes Leak detected",
                path='/',
            )
            return True
        return False

