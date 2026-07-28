#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Debug Endpoint pprof - Exposure Detection',
        'description': 'The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port. This debugging endpoint can potentially leak sensitive information such as internal Kubelet memory addresses and configuration, or for limited denial of service. Versions prior to 1.15.0, 1.14.4, 1.13.8, and 1.12.10 are affected. The issue is of medium severity, but not exposed by the default configuration.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'debug', 'kubernetes', 'kubelet', 'devops', 'unauth', 'disclosure', 'vkev', 'vuln'],
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
            'https://medium.com/bugbountywriteup/my-first-bug-bounty-21d3203ffdb0',
            'http://mmcloughlin.com/posts/your-pprof-is-showing',
            'https://github.com/kubernetes/kubernetes/issues/81023',
            'https://groups.google.com/d/msg/kubernetes-security-announce/pKELclHIov8/BEDtRELACQAJ',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-11248',
        ],
        'cve': 'CVE-2019-11248',
    }

    def run(self):
        for path in ('/debug/pprof/', '/debug/pprof/goroutine?debug=1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Types of profiles available:', 'Profile Descriptions', 'goroutine profile: total',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Debug Endpoint pprof - Exposure detected",
                    path=path,
                )
                return True
        return False

