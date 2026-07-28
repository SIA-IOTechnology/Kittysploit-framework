#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Event Tickets < 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Event Tickets < 5.2.2 - Open Redirect Detection',
        'description': 'WordPress Event Tickets < 5.2.2 is susceptible to an open redirect vulnerability. The plugin does not validate the tribe_tickets_redirect_to parameter before redirecting the user to the given value, leading to an arbitrary redirect issue.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'redirect', 'wp-plugin', 'eventtickets', 'wpscan', 'tri', 'vuln'],
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
            'https://wpscan.com/vulnerability/80b0682e-2c3b-441b-9628-6462368e5fc7',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-25028',
        ],
        'cve': 'CVE-2021-25028',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin.php?page=wp_ajax_rsvp-form&tribe_tickets_redirect_to=https://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress Event Tickets < 5.2.2 - Open Redirect detected",
                path='/wp-admin/admin.php?page=wp_ajax_rsvp-form&tribe_tickets_redirect_to=https://interact.sh',
            )
            return True
        return False

