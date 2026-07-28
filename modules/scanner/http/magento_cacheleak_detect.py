#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magento Cacheleak is an implementation vulnerability, result of bad implementation of web-server configuration."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magento Cacheleak Detection',
        'description': 'Magento Cacheleak is an implementation vulnerability, result of bad implementation of web-server configuration for Magento platform. Magento was developed to work under the Apache web-server which natively works with .htaccess files, so all needed configuration directives specific for various internal Magento folders were placed in .htaccess files. When Magento is installed on web servers that are ignoring .htaccess files (such as nginx), an attacker can get access to internal Magento folders (such as the Magento cache directory) and extract sensitive information from cache files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'magento', 'vuln'],
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
            'https://support.hypernode.com/en/best-practices/security/how-to-secure-magento-cacheleak',
            'https://www.acunetix.com/vulnerabilities/web/magento-cacheleak/',
            'https://royduineveld.nl/magento-cacheleak-exploit/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/var/resource_config.json', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('media_directory', 'allowed_resources',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Magento Cacheleak detected",
                path='/var/resource_config.json',
            )
            return True
        return False

