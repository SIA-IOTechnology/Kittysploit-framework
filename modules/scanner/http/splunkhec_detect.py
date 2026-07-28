#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Splunk HCE (HTTP Event Collector (HEC)) was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Splunk HEC - Detect',
        'description': 'Splunk HCE (HTTP Event Collector (HEC)) was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'splunk', 'hec'],
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
            'https://dev.splunk.com/enterprise/docs/devtools/httpeventcollector/',
            'https://community.splunk.com/t5/Getting-Data-In/How-to-check-if-an-HEC-is-up-or-not-before-posting-any-data-to/td-p/417404',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/services/collector/health', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = ('text\\', 'HEC is healthy\\', 'code',)
        body_word_hit = any(m in body for m in body_markers)
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_markers = ('application/json',)
        if any(m in headers for m in header_markers):
            self.set_info(
                severity='info',
                reason="Splunk HEC detected",
                path='/services/collector/health',
            )
            return True
        return False

