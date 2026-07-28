#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Jolokia Java Heap Information Disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jolokia Java Heap Information Disclosure Detection',
        'description': 'Detects Jolokia Java Heap Information Disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'jolokia', 'disclosure', 'java', 'vuln'],
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
    }

    def run(self):
        path = '/jolokia/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='\n{\n   "type":"EXEC",\n   "mbean":"com.sun.management:type=HotSpotDiagnostic",\n   "operation":"dumpHeap",\n   "arguments":[\n      "/tmp1234/test1.hprof",\n      0\n   ]\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('stacktrace":"java.io.IOException: No such file or directory',)
        if any(m in body for m in body_any):
            self.set_info(severity='info', reason='Jolokia Java Heap Information Disclosure detected', path=path)
            return True
        return False

