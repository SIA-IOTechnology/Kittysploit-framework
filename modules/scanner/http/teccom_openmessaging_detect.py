#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TecCom TecConnect OpenMessaging webservice was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TecConnect OpenMessaging Webservice Detection',
        'description': 'TecCom TecConnect OpenMessaging webservice was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'teccom', 'tecconnect', 'eol', 'wsdl'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
    }

    def run(self):
        for path in ('/openmessaging.asmx?wsdl', '/tecopenmessaging/openmessaging.asmx?wsdl', '/tomconnect/openmessaging.asmx?wsdl', '/tomconnect_apo/openmessaging.asmx?wsdl', '/tompreprod/openmessaging.asmx?wsdl'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('ProcessRequestResponse', 'ProcessRequestResult',)
            ctype_any = ('text/xml',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='info',
                    reason='TecConnect OpenMessaging Webservice detected',
                    path=path,
                )
                return True
        return False

