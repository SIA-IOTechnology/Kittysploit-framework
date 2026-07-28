#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Integrated Dell Remote Access Controller."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dell iDRAC6 - Detect',
        'description': 'Detected Integrated Dell Remote Access Controller. The iDRAC is designed for secure local and remote server management and helps IT administrators deploy, update and monitor Dell EMC PowerEdge servers.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'dell', 'idrac'],
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
        'references': ['https://www.dell.com/support/manuals/en-us/idrac6-monolithic-v1.9/idrac_1.95_ug'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/data?get=prodServerGen', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/xml',)
        body_all = ('<prodServerGen>', '<Manufacturer>', 'Dell', '<isDellBranded>1</isDellBranded>', '11G',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="Dell iDRAC6 detected",
                path='/data?get=prodServerGen',
            )
            return True
        return False

