#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nova noVNC contains an open redirect vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nova noVNC - Open Redirect Detection',
        'description': 'Nova noVNC contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'redirect', 'novnc', 'seclists', 'openstack', 'vuln'],
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
            'https://seclists.org/oss-sec/2021/q3/188',
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3654',
            'https://bugs.python.org/issue32084',
            'https://opendev.org/openstack/nova/commit/04d48527b62a35d912f93bc75613a6cca606df66',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3654',
        ],
        'cve': 'CVE-2021-3654',
    }

    def run(self):
        r = self.http_request(method="GET", path='//interact.sh/%2f..', allow_redirects=False)
        if not r or r.status_code not in (302, 301):
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Nova noVNC - Open Redirect detected",
                path='//interact.sh/%2f..',
            )
            return True
        return False

