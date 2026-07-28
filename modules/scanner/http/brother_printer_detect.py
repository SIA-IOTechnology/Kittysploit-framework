#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Brother printer web interface and management panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Brother Printer Panel - Detect',
        'description': 'Brother printer web interface and management panel was detected. This template identifies exposed Brother printer panels that may be accessible without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'brother', 'printer', 'iot'],
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
            'https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed',
            'https://support.brother.com/g/b/faqend.aspx?c=eu_ot&lang=en&prod=group2&faqid=faq00100846_000',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/general/status.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_markers = (
            'brother industries',
            'brother printer',
            'brother mfc',
            'brother hl',
            'brother dcp',
            'solutions.brother.com',
        )
        if any(m in body for m in body_markers):
            self.set_info(
                severity='info',
                reason="Brother Printer Panel detected",
                path='/general/status.html',
            )
            return True
        return False

