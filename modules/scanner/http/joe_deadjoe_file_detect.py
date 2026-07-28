#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Deadjoe file,this file was created by Joe's Own Editor when a session terminated abnormally."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joe Editor DEADJOE File - Exposure Detection',
        'description': "Detected Deadjoe file,this file was created by Joe's Own Editor when a session terminated abnormally. It contained the full contents of the file being edited at the time of the crash, potentially exposing sensitive information such as passwords, configuration files, or credentials.",
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'deadjoe', 'misconfig', 'files'],
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
            'https://www.acunetix.com/vulnerabilities/web/joe-editor-deadjoe-file/',
            'https://www.invicti.com/web-application-vulnerabilities/joe-editor-deadjoe-file',
            'https://www.freebsd.org/security/advisories/FreeBSD-SA-01:04.joe.asc',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/DEADJOE', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('JOE was aborted', 'modified files were found in JOE', 'JOE when it aborted',)
        body_all = ('***', 'JOE',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Joe Editor DEADJOE File - Exposure detected",
                path='/DEADJOE',
            )
            return True
        return False

