#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DSR devices default credentials (admin:admin)."""

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DSR - Default Credentials Detection',
        'description': (
            'Tries admin:admin against /scgi-bin/platform.cgi on D-Link DSR devices and '
            'looks for authenticated UI markers or already-logged-in session prompts.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'dlink', 'dsr', 'default-credentials', 'auth', 'vuln',
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
        'references': [],
    }

    def run(self):
        path = '/scgi-bin/platform.cgi'
        ua = quote('KittySploit/1.0', safe='')
        payloads = (
            (
                'thispage=index.html&Users.UserName=admin&Users.Password=admin&'
                f'button.login.Users.dashboard=Login&Login.userAgent={ua}&loggedInStatus='
            ),
            (
                'thispage=index.htm&Users.UserName=admin&Users.Password=admin&'
                f'button.login.Users.deviceStatus=Login&Login.userAgent={ua}'
            ),
        )
        markers = (
            '<p>User Already Logged In</p>',
            'User already logged in</td>',
            'Logged in as:',
            'class="btnLogout"',
            '?page=lanSettings.html',
            '?page=deviceInfo.html',
            '<td class="logout"><a href="?page=index.htm">Logout</a></td>',
            '?page=wanWizard.htm',
            '?page=adminSettings.htm',
        )
        for data in payloads:
            r = self.http_request(
                method='POST',
                path=path,
                data=data,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Referer': path,
                },
                allow_redirects=False,
            )
            if not r:
                continue
            body = r.text or ''
            if any(m in body for m in markers):
                self.set_info(
                    severity='high',
                    reason='D-Link DSR default credentials admin:admin accepted',
                    path=path,
                )
                return True
        return False
