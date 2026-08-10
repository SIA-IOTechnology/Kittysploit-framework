#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jenkins default credentials detection (admin/password, admin/admin, ...)."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jenkins - Default Credentials Detection',
        'description': (
            'Tries known Jenkins default credentials (admin:password, admin:admin, '
            'admin:jenkins, jenkins:jenkins) against j_spring_security_check / '
            'j_acegi_security_check and verifies Dashboard access.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'jenkins', 'default-credentials', 'auth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 12,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://docs.openshift.com/container-platform/4.7/openshift_images/using_images/images-other-jenkins.html',
        ],
    }

    base_path = OptString('', 'Optional Jenkins base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def _session_cookie(self, headers_text: str) -> str:
        m = re.search(r'(JSESSIONID\.[^=]+=[a-z0-9]+)', headers_text, re.I)
        return m.group(1) if m else ''

    def run(self):
        prefix = self._prefix()
        from_url = prefix or '/'
        login_path = f'{prefix}/login'
        creds = (
            ('admin', 'password'),
            ('admin', 'admin'),
            ('admin', 'jenkins'),
            ('jenkins', 'jenkins'),
        )
        auth_paths = (
            f'{prefix}/j_spring_security_check',
            f'{prefix}/j_acegi_security_check',
        )

        for user, password in creds:
            for auth_path in auth_paths:
                login = self.http_request(method='GET', path=login_path, allow_redirects=False)
                if not login or login.status_code != 200:
                    continue
                hdrs = '\n'.join(f'{k}: {v}' for k, v in login.headers.items())
                # Also check Set-Cookie from raw cookies dict
                cookie = self._session_cookie(hdrs)
                if not cookie:
                    for k, v in (login.headers or {}).items():
                        if k.lower() == 'set-cookie' and 'JSESSIONID' in v:
                            m = re.search(r'(JSESSIONID\.[^=]+=[a-z0-9]+)', v, re.I)
                            if m:
                                cookie = m.group(1)
                                break
                if not cookie:
                    continue

                if auth_path.endswith('j_spring_security_check'):
                    data = (
                        f'j_username={quote(user)}&j_password={quote(password)}&'
                        f'from={quote(from_url)}&Submit=Sign+in'
                    )
                else:
                    data = (
                        f'j_username={quote(user)}&j_password={quote(password)}&'
                        f'from={quote(from_url)}&Submit=log+in'
                    )

                # Parse cookie name/value for cookies= dict
                if '=' in cookie:
                    cname, cval = cookie.split('=', 1)
                else:
                    continue
                auth = self.http_request(
                    method='POST',
                    path=auth_path,
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    cookies={cname: cval},
                    allow_redirects=False,
                )
                if not auth or auth.status_code not in (302, 301):
                    continue
                auth_hdrs = '\n'.join(f'{k}: {v}' for k, v in auth.headers.items())
                new_cookie = self._session_cookie(auth_hdrs)
                if not new_cookie:
                    for k, v in (auth.headers or {}).items():
                        if k.lower() == 'set-cookie' and 'JSESSIONID' in v:
                            m = re.search(r'(JSESSIONID\.[^=]+=[a-z0-9]+)', v, re.I)
                            if m:
                                new_cookie = m.group(1)
                                break
                if not new_cookie or '=' not in new_cookie:
                    continue
                nname, nval = new_cookie.split('=', 1)
                dash = self.http_request(
                    method='GET',
                    path=from_url,
                    cookies={nname: nval},
                    allow_redirects=False,
                )
                if not dash or dash.status_code != 200:
                    continue
                body = dash.text or ''
                if '<title>Dashboard [Jenkins]</title>' in body and '/logout' in body:
                    self.set_info(
                        severity='high',
                        reason=f'Jenkins default credentials {user}:{password} accepted',
                        path=auth_path,
                    )
                    return True
        return False
