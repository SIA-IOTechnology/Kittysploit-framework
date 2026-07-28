#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Prometheus config API endpoint was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Prometheus Config API Endpoint Discovery Detection',
        'description': 'A Prometheus config API endpoint was discovered. The config endpoint returns the loaded Prometheus configuration file along with the addresses of targets and alerting/discovery services alongside the credentials required to access them. Usually, Prometheus replaces the passwords in the credentials config configuration field with the placeholder <secret> (although this still leaks the username).',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'prometheus', 'config', 'misconfig', 'vuln'],
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
        'references': ['https://jfrog.com/blog/dont-let-prometheus-steal-your-fire/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/status/config', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"status": "success":', '"data":', '"yaml":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='info',
                reason="Prometheus Config API Endpoint Discovery detected",
                path='/api/v1/status/config',
            )
            return True
        return False

