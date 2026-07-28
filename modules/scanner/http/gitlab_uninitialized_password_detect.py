#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prior to version 14, GitLab installations required a root password to be set via the web UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Uninitialized GitLab instances Detection',
        'description': 'Prior to version 14, GitLab installations required a root password to be set via the web UI. If the administrator skipped this step, any visitor could set a password and control the instance.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'gitlab', 'misconfig', 'unauth', 'vuln'],
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
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://gitlab.com/gitlab-org/gitlab/-/issues/211328',
            'https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/5331',
            'https://docs.gitlab.com/omnibus/installation/#set-up-the-initial-password',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/users/sign_in', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Change your password', 'New password', 'Confirm new password',)
        header_any = ('gitlab_session',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Uninitialized GitLab instances detected",
                path='/users/sign_in',
            )
            return True
        return False

