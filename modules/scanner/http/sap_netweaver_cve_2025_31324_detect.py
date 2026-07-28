#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAP NetWeaver Visual Composer CVE-2025-31324 (unauth metadata uploader) detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP NetWeaver CVE-2025-31324 Detection',
        'description': (
            'Detects unauthenticated access to SAP NetWeaver Visual Composer '
            'Metadata Uploader (CVE-2025-31324) without uploading a malicious payload.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'sap', 'netweaver',
            'rce', 'kev', 'vkev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
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
                'produces_capabilities': [
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-31324',
            'https://me.sap.com/notes/3594142',
            'https://www.bleepingcomputer.com/news/security/sap-fixes-suspected-netweaver-zero-day-exploited-in-attacks/',
        ],
        'cve': 'CVE-2025-31324',
    }

    def run(self):
        get_path = '/developmentserver/metadatauploader'
        r = self.http_request(method='GET', path=get_path, allow_redirects=False)
        if r and r.status_code == 200:
            body = r.text or ''
            markers = (
                'MetadataUploader',
                'Visual Composer',
                ' sap-ui-',
                'SAP NetWeaver',
                'com.sap.',
            )
            has_sap = any(m in body for m in markers)
            post_path = '/developmentserver/metadatauploader?CONTENTTYPE=MODEL&CLIENT=1'
            boundary = '----KSBoundary7MA4YWxkTrZu0gW'
            harmless = (
                f'--{boundary}\r\n'
                'Content-Disposition: form-data; name="file"; filename="ks-probe.txt"\r\n'
                'Content-Type: text/plain\r\n'
                '\r\n'
                'kittysploit-probe\r\n'
                f'--{boundary}--\r\n'
            )
            pr = self.http_request(
                method='POST',
                path=post_path,
                allow_redirects=False,
                headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
                data=harmless,
            )
            if pr and pr.status_code not in (401, 403, 404):
                pbody = pr.text or ''
                processed = 'FAILED' in pbody and 'Cause' in pbody
                if processed or (has_sap and pr.status_code in (200, 500)):
                    self.set_info(
                        severity='critical',
                        reason=(
                            'SAP NetWeaver CVE-2025-31324 Metadata Uploader '
                            'accessible without authentication'
                        ),
                        path=post_path,
                        evidence=f'GET={r.status_code} POST={pr.status_code}',
                    )
                    return True

        # Fallback: POST-only if GET blocked differently
        post_path = '/developmentserver/metadatauploader?CONTENTTYPE=MODEL&CLIENT=1'
        boundary = '----KSBoundary7MA4YWxkTrZu0gW'
        harmless = (
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="file"; filename="ks-probe.txt"\r\n'
            'Content-Type: text/plain\r\n'
            '\r\n'
            'kittysploit-probe\r\n'
            f'--{boundary}--\r\n'
        )
        pr = self.http_request(
            method='POST',
            path=post_path,
            allow_redirects=False,
            headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
            data=harmless,
        )
        if not pr or pr.status_code in (401, 403, 404):
            return False
        pbody = pr.text or ''
        if 'FAILED' in pbody and 'Cause' in pbody:
            self.set_info(
                severity='critical',
                reason=(
                    'SAP NetWeaver CVE-2025-31324 Metadata Uploader '
                    'processed unauthenticated upload'
                ),
                path=post_path,
                evidence=f'POST={pr.status_code} FAILED/Cause',
            )
            return True
        return False
