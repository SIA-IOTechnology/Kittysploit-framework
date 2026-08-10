#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identifies Drupal sites with the elfinder library installed, which could be vulnerable to unrestricted file up."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drupal 7 Elfinder - Unauthenticated Connector Exposure Detection',
        'description': 'Identifies Drupal sites with the elfinder library installed, which could be vulnerable to unrestricted file upload through the connector.php file.When this component is detected, the site may be vulnerable to remote code execution attacks via PHP file uploads.This template only detects the presence of the vulnerable component and does not perform any exploitation.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'drupal', 'elfinder', 'filemanager', 'exposure', 'vuln'],
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/Kro0oz/drupal-7-elfinder'],
    }

    def run(self):
        path = '/sites/all/libraries/elfinder/connectors/php/connector.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('{"cwd":',)
        ctype_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='Drupal 7 elfinder connector.php exposed (upload/RCE surface, not confirmed RCE)',
                path=path,
            )
            return True
        return False

