#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SFTP configuration file was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SFTP Configuration File - Credentials Exposure Detection',
        'description': 'SFTP configuration file was detected.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'sftp', 'config', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://blog.sucuri.net/2012/11/psa-sftpftp-password-exposure-via-sftp-config-json.html',
            'https://www.acunetix.com/vulnerabilities/web/sftp-ftp-credentials-exposure/',
            'https://codexns.io/products/sftp_for_sublime/settings',
        ],
    }

    def run(self):
        for path in ('/sftp-config.json', '/ftpsync.settings'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('"host":', '"user":', '"password":', '"remote_path":', 'file_permissions', 'extra_list_connections',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="SFTP Configuration File - Credentials Exposure detected",
                    path=path,
                )
                return True
        return False

