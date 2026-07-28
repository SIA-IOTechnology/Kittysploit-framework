#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The targets endpoint exposes services belonging to the infrastructure, including their roles and labels."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Prometheus targets API endpoint Detection',
        'description': "The targets endpoint exposes services belonging to the infrastructure, including their roles and labels. In addition to showing the target machine addresses, the endpoint also exposes metadata labels that are added by the target provider. These labels are intended to contain non-sensitive values, like the name of the server or its description, but various cloud platforms may automatically expose sensitive data in these labels, oftentimes without the developer's knowledge.",
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'prometheus', 'misconfig', 'vuln'],
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
        r = self.http_request(method="GET", path='/api/v1/targets', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"status": "success"', '"data":', '"labels":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='info',
                reason="Prometheus targets API endpoint detected",
                path='/api/v1/targets',
            )
            return True
        return False

