#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""National Instruments (LabVIEW) Service Locator detected and enumerated."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LabVIEW/NI Service Locator Detection',
        'description': 'National Instruments (LabVIEW) Service Locator detected and enumerated. This services leaks a list of all services provided by the device, hardware capabilities and possibly versions. These hardware devices should not be exposed to the internet.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'iot', 'labview', 'panel', 'enumeration'],
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
            'https://forums.ni.com/t5/LabVIEW/Get-list-of-services-from-NI-service-locator/td-p/3850515',
            'https://www.ni.com/en/support/security/configuring-software-and-hardware-firewalls-to-support-national-.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/dumpinfo', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Service Locator URL Mappings', 'National Instruments',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="LabVIEW/NI Service Locator detected",
                path='/dumpinfo',
            )
            return True
        return False

