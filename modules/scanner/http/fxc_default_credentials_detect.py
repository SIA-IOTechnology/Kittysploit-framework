#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FXC router HTTP default credentials admin:admin."""

import time
from datetime import datetime, timezone
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FXC Router - Default Credentials (admin/admin)',
        'description': (
            'Detects FXC (and related) router web UIs accepting default credentials '
            'admin:admin via /cgi-bin/login.apply or /cgi/login.cgi.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'fxc', 'router', 'iot', 'default-login',
            'default-credentials', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 0.9,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.greenbone.net/',
        ],
    }

    def run(self):
        username = 'admin'
        password = 'admin'
        r0 = self.http_request(method='GET', path='/', allow_redirects=False)
        body0 = (r0.text or '') if r0 else ''

        if r0 and '/cgi-bin/login.apply' in body0:
            now = datetime.now(timezone.utc)
            hashstr = now.strftime('%Y%m%d%H%M')
            cookie_no = str(int(time.time()))[-6:]
            path = '/cgi-bin/login.apply'
            post_data = (
                f'username_input={username}&password_input={password}&lang=en_EN'
                f'&hashstr={hashstr}&username={username}&password={password}'
            )
            r = self.http_request(
                method='POST',
                path=path,
                data=post_data,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': f'cookieno={cookie_no}; username={username}; password={password}',
                },
                allow_redirects=False,
            )
            if (
                r
                and r.status_code in (200, 301, 302, 303, 307, 308)
                and "window.open('/home.htm'" in (r.text or '')
            ):
                self.set_info(
                    severity='critical',
                    reason='FXC router default credentials accepted (admin/admin)',
                    path=path,
                )
                return True
            return False

        # Alternate FXC login CGI — only attempt when the UI looks related.
        if not r0 or 'login.cgi' not in body0:
            return False

        path = '/cgi/login.cgi'
        r = self.http_request(
            method='POST',
            path=path,
            data=f'username={username}&password={password}',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest',
            },
            allow_redirects=False,
        )
        if not r or r.status_code not in (200, 301, 302, 303, 307, 308):
            return False
        body = (r.text or '').lower()
        if not body or 'login error' in body:
            return False
        if not any(x in body for x in ('success', 'ok', 'home', 'index', 'loginok')):
            if r.status_code not in (301, 302, 303, 307, 308):
                return False
        self.set_info(
            severity='critical',
            reason='FXC router default credentials accepted (admin/admin)',
            path=path,
        )
        return True
