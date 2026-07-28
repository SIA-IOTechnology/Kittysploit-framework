#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Google Cloud Ignore File Exposure Detection',
        'description': 'Detected exposed .gcloudignore files which may reveal directory structure,deployment configurations, and sensitive project information used by Google Cloud SDK (gcloud) during deployments.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'gcloud', 'google', 'config', 'files', 'cloud'],
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
        'references': ['https://cloud.google.com/sdk/gcloud/reference/topic/gcloudignore'],
    }

    def run(self):
        path = '/.gcloudignore'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('deployment', 'Cloud Build',)
        ctype_any = ('application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='low',
                reason='Google Cloud Ignore File Exposure detected',
                path=path,
            )
            return True
        return False

