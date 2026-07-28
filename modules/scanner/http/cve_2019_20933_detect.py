#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""InfluxDB before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'InfluxDB <1.7.6 - Authentication Bypass Detection',
        'description': 'InfluxDB before 1.7.6 contains an authentication bypass vulnerability via the authenticate function in services/httpd/handler.go. A JWT token may have an empty SharedSecret (aka shared secret). An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'unauth', 'db', 'influxdb', 'misconfig', 'influxdata', 'vkev', 'vuln'],
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
            'https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20933',
            'https://github.com/influxdata/influxdb/compare/v1.7.5...v1.7.6',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-20933',
            'https://github.com/influxdata/influxdb/commit/761b557315ff9c1642cf3b0e5797cd3d983a24c0',
        ],
        'cve': 'CVE-2019-20933',
    }

    def run(self):
        r = self.http_request(method="GET", path='/query?db=db&q=SHOW%20DATABASES', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"results":', '"name":"databases"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="InfluxDB <1.7.6 - Authentication Bypass detected",
                path='/query?db=db&q=SHOW%20DATABASES',
            )
            return True
        return False

