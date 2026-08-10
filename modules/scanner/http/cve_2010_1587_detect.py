#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2010-1587 by requesting //admin/queues."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache ActiveMQ - Double-Slash Source Disclosure Detection (CVE-2010-1587)',
        'description': (
            'Detects CVE-2010-1587 by requesting //admin/queues.jsp and matching the raw '
            'JSP expression ${sessionScope["secret"]} in the response body.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'activemq', 'disclosure', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.8,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2010-1587',
        ],
        'cve': 'CVE-2010-1587',
    }

    def run(self):
        # Greenbone confirms raw JSP EL, not generic "<%" (too common in apps/docs).
        marker = '${sessionScope["secret"]}'
        for path in ('//admin/queues.jsp', '/admin//queues.jsp'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            body = (r.text or '') if r else ''
            if marker in body:
                self.set_info(
                    severity='medium',
                    reason='ActiveMQ double-slash source disclosure (CVE-2010-1587)',
                    path=path,
                )
                return True
        return False

