#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kibana versions before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kibana Timelion - Arbitrary Code Execution Detection',
        'description': 'Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'kibana', 'rce', 'kev', 'elastic', 'vkev', 'vuln'],
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
            'https://github.com/mpgn/CVE-2019-7609',
            'https://discuss.elastic.co/t/elastic-stack-6-6-1-and-5-6-15-security-update/169077',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-7609',
            'https://www.elastic.co/community/security',
            'https://access.redhat.com/errata/RHBA-2019:2824',
        ],
        'cve': 'CVE-2019-7609',
    }

    def run(self):
        path = '/api/timelion/run'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json; charset=utf-8'}, data='{"sheet":[".es(*)"],"time":{"from":"now-1m","to":"now","mode":"quick","interval":"auto","timezone":"Asia/Shanghai"}}')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('seriesList',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason='Kibana Timelion - Arbitrary Code Execution detected',
                path=path,
            )
            return True
        return False

