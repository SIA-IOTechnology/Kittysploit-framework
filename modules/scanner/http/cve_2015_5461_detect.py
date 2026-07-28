#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress StageShow plugin before 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress StageShow <5.0.9 - Open Redirect Detection',
        'description': 'WordPress StageShow plugin before 5.0.9 contains an open redirect vulnerability in the Redirect function in stageshow_redirect.php. A remote attacker can redirect users to arbitrary web sites and conduct phishing attacks via a malicious URL in the url parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'wpscan', 'seclists', 'redirect', 'wordpress', 'wp-plugin', 'stageshow_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/afc0d5b5-280f-424f-bc3e-d04452e56e16',
            'https://wordpress.org/plugins/stageshow/changelog/',
            'http://seclists.org/fulldisclosure/2015/Jul/27',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-5461',
            'https://plugins.trac.wordpress.org/changeset/1165310/',
        ],
        'cve': 'CVE-2015-5461',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/stageshow/stageshow_redirect.php?url=http%3A%2F%2Finteract.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress StageShow <5.0.9 - Open Redirect detected",
                path='/wp-content/plugins/stageshow/stageshow_redirect.php?url=http%3A%2F%2Finteract.sh',
            )
            return True
        return False

