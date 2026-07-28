#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A SQL injection vulnerability in mod_mysql_vhost."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lighttpd 1.4.34 SQL Injection and Path Traversal Detection',
        'description': 'A SQL injection vulnerability in mod_mysql_vhost.c in lighttpd before 1.4.35 allows remote attackers to execute arbitrary SQL commands via the host name (related to request_check_hostname).',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'lighttpd', 'injection', 'seclists', 'sqli', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-2323',
            'https://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt',
            'http://www.lighttpd.net/2014/3/12/1.4.35/',
            'http://seclists.org/oss-sec/2014/q1/561',
            'http://jvn.jp/en/jp/JVN37417423/index.html',
        ],
        'cve': 'CVE-2014-2323',
    }

    def run(self):
        path = '/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Lighttpd 1.4.34 SQL Injection and Path Traversal detected', path=path)
            return True
        return False

