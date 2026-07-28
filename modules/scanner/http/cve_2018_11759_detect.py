#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Tomcat JK (mod_jk) Connector 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Tomcat JK Connect <=1.2.44 - Manager Access Detection',
        'description': 'Apache Tomcat JK (mod_jk) Connector 1.2.0 to 1.2.44 allows specially constructed requests to expose application functionality through the reverse proxy. It is also possible in some configurations for a specially constructed request to bypass the access controls configured in httpd. While there is some overlap between this issue and CVE-2018-1323, they are not identical.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'apache', 'tomcat', 'httpd', 'mod-jk', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/immunIT/CVE-2018-11759',
            'https://lists.apache.org/thread.html/6d564bb0ab73d6b3efdd1d6b1c075d1a2c84ecd84a4159d6122529ad@%3Cannounce.tomcat.apache.org%3E',
            'https://lists.debian.org/debian-lts-announce/2018/12/msg00007.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-11759',
            'https://access.redhat.com/errata/RHSA-2019:0366',
        ],
        'cve': 'CVE-2018-11759',
    }

    def run(self):
        for path in ('/jkstatus', '/jkstatus;'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('JK Status Manager',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Apache Tomcat JK Connect <=1.2.44 - Manager Access detected",
                    path=path,
                )
                return True
        return False

