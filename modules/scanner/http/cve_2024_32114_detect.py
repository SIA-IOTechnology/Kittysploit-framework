#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache ActiveMQ 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache ActiveMQ 6.x < 6.1.2 - Broken Access Control Detection',
        'description': 'Apache ActiveMQ 6.x contains an unauthenticated API web context caused by default configuration lacking security measures in the Jetty server, letting anyone interact with broker APIs and messaging layers, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'activemq', 'apache', 'jolokia', 'vkev'],
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
            'https://activemq.apache.org/security-advisories.data/CVE-2024-32114-announcement.txt',
            'https://github.com/vulhub/vulhub/tree/master/activemq/CVE-2024-32114',
            'https://github.com/advisories/GHSA-gj5m-m88j-v7c3',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-32114',
        ],
        'cve': 'CVE-2024-32114',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/jolokia/search/org.apache.activemq:type=Broker,*', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/plain',)
        body_all = ('request\\', ':', 'org.apache.activemq')
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Apache ActiveMQ 6.x < 6.1.2 - Broken Access Control detected",
                path='/api/jolokia/search/org.apache.activemq:type=Broker,*',
            )
            return True
        return False

