#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Newspaper Theme versions 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Newspaper Theme 6.4–6.7.1 - Privilege Escalation Detection',
        'description': 'Newspaper Theme versions 6.4 to 6.7.1 for WordPress lacked proper options access control through td_ajax_update_panel, which led to a Privilege Escalation vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'wpscan', 'cve2016', 'wp', 'wordpress', 'wp-theme', 'newspaper', 'passive', 'vkev', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/5365ecca-93e2-4bfc-bd4a-6f61d7d75e96/'],
        'cve': 'CVE-2016-10972',
    }

    def run(self):
        path = '/wp-content/themes/Newspaper/style.css'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Newspaper',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='Newspaper Theme 6.4–6.7.1 - Privilege Escalation detected',
                path=path,
            )
            return True
        return False

