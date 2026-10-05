#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SharePoint ToolShell auth bypass (CVE-2025-53771) and ToolPane surface (CVE-2025-53770)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SharePoint ToolShell CVE-2025-53770 Detection',
        'description': (
            'Detects on-premises Microsoft SharePoint ToolShell exposure: '
            'unauthenticated access to ToolPane.aspx via Referer bypass '
            '(CVE-2025-53771) and unsafe deserialization surface (CVE-2025-53770).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': ['CVE-2025-53770', 'CVE-2025-53771'],
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-53770',
            'https://censys.com/advisory/cve-2025-53770/',
        ],
        'tags': ['web', 'scanner', 'sharepoint', 'toolshell', 'deserialization', 'kev', 'microsoft'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.5,
            'requires': {'tech_hints_any': ['sharepoint']},
            'chain': {
                'produces_capabilities': [{'capability': 'cve_indicator', 'from_detail': ''}],
                'suggested_followups': [
                    'exploits/windows/http/sharepoint_toolshell_cve_2025_53770_rce',
                    'scanner/http/sharepoint_toolshell_backdoor_detect',
                ],
            },
        },
    }

    port = OptPort(443, 'SharePoint HTTPS port', required=True)
    ssl = OptBool(True, 'Use HTTPS', required=True)

    def run(self):
        toolpane = '/_layouts/15/ToolPane.aspx?DisplayMode=Edit'
        signout = '/_layouts/SignOut.aspx'
        baseline = self.http_request(method='GET', path=toolpane, allow_redirects=False)
        if not baseline:
            return False
        if baseline.status_code in (401, 403):
            bypass = self.http_request(
                method='GET',
                path=toolpane,
                headers={'Referer': signout},
                allow_redirects=False,
            )
            if not bypass or bypass.status_code in (401, 403):
                return False
            body = (bypass.text or '').lower()
            if 'toolpane' not in body and 'viewstate' not in body:
                return False
            self.set_info(
                severity='critical',
                reason='SharePoint ToolPane auth bypass via Referer (CVE-2025-53771)',
                path=toolpane,
                cve='CVE-2025-53771',
            )
            return True
        headers_blob = '\n'.join(f'{k}: {v}' for k, v in baseline.headers.items()).lower()
        if 'microsoftsharepointteamservices' in headers_blob or 'sharepoint' in (baseline.text or '').lower():
            if '__viewstate' in (baseline.text or '').lower():
                self.set_info(
                    severity='critical',
                    reason='SharePoint ToolPane.aspx exposed without authentication (ToolShell surface)',
                    path=toolpane,
                    cve='CVE-2025-53770',
                )
                return True
        return False
