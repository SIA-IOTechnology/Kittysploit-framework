#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KNIME Server (and its successor KNIME Business Hub), a commercial platform from KNIME AG for deploying, execut."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KNIME Server / Business Hub WebPortal - Detect',
        'description': 'KNIME Server (and its successor KNIME Business Hub), a commercial platform from KNIME AG for deploying, executing, and managing data-science and machine learning workflows built in the KNIME Analytics Platform, was detected. An exposed WebPortal login page was identified, including white-labeled/rebranded deployments, via their underlying static asset paths.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'knime', 'ml', 'ai', 'data-science'],
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
            'https://www.knime.com/knime-software/knime-server',
            'https://www.knime.com/knime-business-hub',
            'https://docs.knime.com/latest/business_hub_admin_guide/index.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'webportal/_nuxt/theme/favicon',
            '_login/_nuxt',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="KNIME Server / Business Hub WebPortal detected",
                path='/',
            )
            return True
        return False

