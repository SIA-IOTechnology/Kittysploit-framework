#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CouchCMS <= 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CouchCMS <= 2.0 - Path Disclosure Detection',
        'description': 'CouchCMS <= 2.0 allows remote attackers to discover the full path via a direct request to includes/mysql2i/mysql2i.func.php or addons/phpmailer/phpmailer.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'couchcms', 'fpd', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/CouchCMS/CouchCMS/issues/46',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7662',
            'https://github.com/20142995/Goby',
            'https://github.com/5ecurity/CVE-List',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-7662',
    }

    def run(self):
        for path in ('/includes/mysql2i/mysql2i.func.php', '/addons/phpmailer/phpmailer.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('mysql2i.func.php on line 10', 'Fatal error: Cannot redeclare mysql_affected_rows() in', 'phpmailer.php on line 10', 'Fatal error: Call to a menber function add_event_listener() on a non-object in',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="CouchCMS <= 2.0 - Path Disclosure detected",
                    path=path,
                )
                return True
        return False

