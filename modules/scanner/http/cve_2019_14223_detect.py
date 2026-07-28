#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alfresco Share before 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Alfresco Share - Open Redirect Detection',
        'description': 'Alfresco Share before 5.2.6, 6.0.N and 6.1.N contains an open redirect vulnerability via a crafted POST request. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'redirect', 'alfresco', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://community.alfresco.com/content?filterID=all~objecttype~thread%5Bquestions%5D',
            'https://github.com/DrunkenShells/Disclosures/tree/master/CVE-2019-14223-Open%20Redirect%20in%20Alfresco%20Share-Alfresco%20Community',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-14223',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2019-14223',
    }

    def run(self):
        path = '/share/page/dologin'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='success=%2Fshare%2Fpage%2F&failure=:\\\\interact.sh&username=baduser&password=badpass\n')
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*:\\s*)(?:https?://|//|\\\\)?(?:[a-zA-Z0-9\\-_]*\\.)?interact\\.sh(?:\\s*)$',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(
                severity='medium',
                reason='Alfresco Share - Open Redirect detected',
                path=path,
            )
            return True
        return False

