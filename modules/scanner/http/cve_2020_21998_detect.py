#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HomeAutomation 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HomeAutomation 3.3.2 - Open Redirect Detection',
        'description': "HomeAutomation 3.3.2 contains a redirect vulnerability caused by improper verification of the 'redirect' GET parameter in 'api.php', letting attackers redirect users to arbitrary websites, exploit requires user interaction with a crafted link.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'homeautomation', 'packetstorm', 'iot', 'redirect', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5559.php',
            'https://packetstormsecurity.com/files/155795/HomeAutomation-3.3.2-Open-Redirect.html',
            'https://cxsecurity.com/issue/WLB-2019120132',
        ],
        'cve': 'CVE-2020-21998',
    }

    def run(self):
        r = self.http_request(method="GET", path='/homeautomation_v3_3_2/api.php?do=groups/toggle&groupid=1&status=1&redirect=https://interact.sh/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="HomeAutomation 3.3.2 - Open Redirect detected",
                path='/homeautomation_v3_3_2/api.php?do=groups/toggle&groupid=1&status=1&redirect=https://interact.sh/',
            )
            return True
        return False

