#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitLab CE/EE ExifTool RCE unpatched fingerprint (CVE-2021-22205)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GitLab - ExifTool RCE Unpatched Fingerprint (CVE-2021-22205)',
        'description': (
            'Detects unpatched GitLab instances vulnerable to CVE-2021-22205 by POSTing a '
            'multipart JPEG upload to a random path and looking for HTTP 422 with '
            '"The change you requested was rejected" (Greenbone active check).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2021', 'gitlab', 'rce', 'exiftool',
            'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-10-3-released/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-22205',
        ],
        'cve': 'CVE-2021-22205',
    }

    def run(self):
        bound = f'_{secrets.token_hex(8)}'
        name = secrets.token_hex(6)
        path = f'/{secrets.token_hex(4)}'
        body = (
            f'--{bound}\r\n'
            f'Content-Disposition: form-data; name="file"; filename="{name}.jpg"\r\n'
            'Content-Type: image/jpeg\r\n'
            'Content-Transfer-Encoding: binary\r\n\r\n'
            f'{secrets.token_hex(16)}\r\n'
            f'--{bound}--\r\n'
        )
        r = self.http_request(
            method='POST',
            path=path,
            data=body,
            headers={'Content-Type': f'multipart/form-data; boundary={bound}'},
            allow_redirects=False,
        )
        if not r or r.status_code != 422:
            return False
        text = r.text or ''
        headers = {str(k).lower(): str(v) for k, v in (r.headers or {}).items()}
        # Soft version fingerprint — require GitLab-shaped rejection, not any 422.
        gitlabish = (
            'gitlab' in text.lower()
            or 'x-gitlab' in ' '.join(headers)
            or any(k.startswith('x-gitlab') for k in headers)
            or 'gon.gitlab' in text.lower()
        )
        if gitlabish and 'The change you requested was rejected' in text:
            self.set_info(
                severity='high',
                reason='GitLab unpatched fingerprint for CVE-2021-22205 (422 rejected upload)',
                path=path,
            )
            return True
        return False
