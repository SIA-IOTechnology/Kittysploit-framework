#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Puppet Server and PuppetDB provide useful performance and debugging information via their metrics API endpoint."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Puppet Server/PuppetDB - Sensitive Information Disclosure Detection',
        'description': 'Puppet Server and PuppetDB provide useful performance and debugging information via their metrics API endpoints, which may contain sensitive information when left exposed.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'puppet', 'exposure', 'puppetdb', 'vuln'],
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
            'https://puppet.com/security/cve/CVE-2020-7943',
            'https://tickets.puppetlabs.com/browse/PDB-4876',
            'https://puppet.com/security/cve/CVE-2020-7943/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-7943',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-7943',
    }

    def run(self):
        r = self.http_request(method="GET", path='/metrics/v1/mbeans', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('trapperkeeper',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Puppet Server/PuppetDB - Sensitive Information Disclosure detected",
                path='/metrics/v1/mbeans',
            )
            return True
        return False

