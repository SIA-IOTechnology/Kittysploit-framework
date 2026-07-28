#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache NiFi is designed for data streaming."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache NiFi - Remote Code Execution Detection',
        'description': 'Apache NiFi is designed for data streaming. It supports highly configurable data routing, transformation, and system mediation logic that indicate graphs. The system has unauthorized remote command execution vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'apache', 'nifi', 'rce', 'vuln'],
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
            'https://github.com/imjdl/Apache-NiFi-Api-RCE',
            'https://labs.withsecure.com/tools/metasploit-modules-for-rce-in-apache-nifi-and-kong-api-gateway',
            'https://packetstormsecurity.com/files/160260/apache_nifi_processor_rce.rb.txt',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/nifi-api/process-groups/root', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('revision', 'canRead', 'permissions',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Apache NiFi - Remote Code Execution detected",
                path='/nifi-api/process-groups/root',
            )
            return True
        return False

