#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Brandfolder is vulnerable to remote/local file inclusion and allows remote attackers to inject an ar."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Brandfolder - Open Redirect (RFI & LFI) Detection',
        'description': "WordPress Brandfolder is vulnerable to remote/local file inclusion and allows remote attackers to inject an arbitrary URL into the 'callback.php' endpoint via the 'wp_abspath' parameter which will redirect the victim to it.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wp', 'brandfolder', 'edb', 'wpscan', 'wp-plugin', 'redirect', 'rfi', 'wordpress', 'lfi', 'vuln'],
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
            'https://www.exploit-db.com/exploits/39591',
            'https://wpscan.com/vulnerability/f850e182-f9c6-4264-b2b1-e587447fe4b1',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/brandfolder/callback.php?wp_abspath=https://interact.sh/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress Brandfolder - Open Redirect (RFI & LFI) detected",
                path='/wp-content/plugins/brandfolder/callback.php?wp_abspath=https://interact.sh/',
            )
            return True
        return False

