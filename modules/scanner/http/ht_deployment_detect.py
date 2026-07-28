#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FTP Deployment cache file that contains whole files structure with paths to potentially sensitive files."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': '.htdeployment - Files Tree Cache File Detection',
        'description': 'FTP Deployment cache file that contains whole files structure with paths to potentially sensitive files.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'files', 'php', 'deployment', 'cache', 'dg', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/dg/ftp-deployment/tree/master',
            'https://github.com/dg/ftp-deployment/blob/master/src/Deployment/Deployer.php#L206',
        ],
    }

    def run(self):
        for path in ('/.htdeployment', '/.deployment'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('[config]', '1F 8B',)
            header_any = ('application/octet-stream', 'text/plain',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason=".htdeployment - Files Tree Cache File detected",
                    path=path,
                )
                return True
        return False

