#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Advantech WebAccess/SCADA login panel, a web-browser-based HMI/SCADA software used in critical manufa."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Advantech WebAccess/SCADA - Panel Detection',
        'description': 'Detected Advantech WebAccess/SCADA login panel, a web-browser-based HMI/SCADA software used in critical manufacturing, energy, and water systems.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'ics', 'scada', 'hmi', 'advantech', 'webaccess'],
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
            'https://www.advantech.com/en-us/products/webaccess-scada/sub_a7b4308c-a3d0-446c-8f03-0d098d4b2c31',
            'https://www.cisa.gov/news-events/ics-advisories/icsa-23-150-01',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/broadWeb/bwRoot.asp', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Advantech', 'bw_templete1.dwt', 'WebAccessClientSetup',)
        body_all = ('broadWeb', 'WebAccess',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="Advantech WebAccess/SCADA detected",
                path='/broadWeb/bwRoot.asp',
            )
            return True
        return False

