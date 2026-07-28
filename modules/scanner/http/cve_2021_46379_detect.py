#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DLink DIR850 ET850-1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR850 ET850-1.08TRb03 - Open Redirect Detection',
        'description': 'DLink DIR850 ET850-1.08TRb03 contains incorrect access control vulnerability in URL redirection, which can be used to mislead users to go to untrusted sites.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'redirect', 'dlink', 'router', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-46379',
            'https://drive.google.com/file/d/1rrlwnIxSHEoO4SMAHRPKZSRzK5MwZQRf/view',
            'https://www.dlink.com/en/security-bulletin',
            'https://www.dlink.com/en/security-bulletin/',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-46379',
    }

    def run(self):
        r = self.http_request(method="GET", path='/boafrm/formWlanRedirect?redirect-url=http://interact.sh&wlan_id=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="D-Link DIR850 ET850-1.08TRb03 - Open Redirect detected",
                path='/boafrm/formWlanRedirect?redirect-url=http://interact.sh&wlan_id=1',
            )
            return True
        return False

