#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMware vRealize Log Insight contains an Information Disclosure Vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VMware vRealize Log Insight < v8.10.2 - Information Disclosure Detection',
        'description': 'VMware vRealize Log Insight contains an Information Disclosure Vulnerability. A malicious actor can remotely collect sensitive session and application information without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'vmware', 'exposure', 'passive', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'http://packetstormsecurity.com/files/174606/VMware-vRealize-Log-Insight-Unauthenticated-Remote-Code-Execution.html',
            'https://github.com/horizon3ai/vRealizeLogInsightRCE',
        ],
        'cve': 'CVE-2022-31711',
    }

    def run(self):
        for path in ('/i18n/component/JS?locale=en-US', '/api/v1/version'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('logInsight', 'releaseName\\',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='medium',
                    reason='VMware vRealize Log Insight < v8.10.2 - Information Disclosure detected',
                    path=path,
                )
                return True
        return False

