#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Apache mod_proxy_cluster management interface provides administrative control and visibility into the load."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache `mod_proxy_cluster` Cluster Manager Interface - Exposure Detection',
        'description': 'The Apache mod_proxy_cluster management interface provides administrative control and visibility into the load balancer’s nodes and contexts.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'apache', 'mod_proxy', 'cluster', 'exposure'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
        'references': ['https://httpd.apache.org/docs/2.4/mod/mod_proxy_cluster.html'],
    }

    def run(self):
        for path in ('/mcm', '/cluster-manager', '/mod_cluster_manager'):
            r = self.http_request(method='GET', path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('Mod_cluster Status', 'Protocol supported', 'mod_proxy_cluster',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='info',
                    reason='Apache `mod_proxy_cluster` Cluster Manager Interface - Exposure detected',
                    path=path,
                )
                return True
        return False

