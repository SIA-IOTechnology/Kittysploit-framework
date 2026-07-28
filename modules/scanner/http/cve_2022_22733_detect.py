#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Apache ShardingSphere ElasticJob-U."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache ShardingSphere ElasticJob-UI privilege escalation Detection',
        'description': 'Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Apache ShardingSphere ElasticJob-UI allows an attacker who has guest account to do privilege escalation. This issue affects Apache ShardingSphere ElasticJob-UI Apache ShardingSphere ElasticJob-UI 3.x version 3.0.0 and prior versions.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'exposure', 'sharingsphere', 'apache', 'vuln'],
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
            'https://www.vicarius.io/vsociety/blog/cve-2022-22733-apache-shardingsphere-elasticjob-ui-privilege-escalation',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-22733',
            'https://lists.apache.org/thread/qpdsm936n9bhksb0rzn6bq1h7ord2nm6',
            'http://www.openwall.com/lists/oss-security/2022/01/20/2',
            'https://github.com/Zeyad-Azima/CVE-2022-22733',
        ],
        'cve': 'CVE-2022-22733',
    }

    def run(self):
        path = '/api/login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'application/json, text/plain, */*', 'Access-Token': '', 'Content-Type': 'application/json;charset=UTF-8', 'Origin': '{{RootURL}}', 'Referer': '{{RootURL}}'}, data='{"username":"guest","password":"guest"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"success":true', '"isGuest":true', '"accessToken":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Apache ShardingSphere ElasticJob-UI privilege escalation detected', path=path)
            return True
        return False

