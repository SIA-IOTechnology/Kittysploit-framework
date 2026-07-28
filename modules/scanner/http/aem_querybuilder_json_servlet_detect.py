#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sensitive information might be exposed via AEMs QueryBuilderServlet or QueryBuilderFeedServlet."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AEM QueryBuilder Json Servlet Detection',
        'description': 'Sensitive information might be exposed via AEMs QueryBuilderServlet or QueryBuilderFeedServlet.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'aem', 'adobe', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
            'https://helpx.adobe.com/experience-manager/6-3/sites/developing/using/querybuilder-predicate-reference.html',
            'https://github.com/thomashartm/burp-aem-scanner/blob/master/src/main/java/burp/actions/dispatcher/QueryBuilderExposed.java',
        ],
    }

    def run(self):
        for path in ('/bin/querybuilder.json', '/bin/querybuilder.json.servlet', '///bin///querybuilder.json', '///bin///querybuilder.json.servlet', '/bin/querybuilder.feed', '/bin/querybuilder.feed.servlet', '///bin///querybuilder.feed', '/ ///bin///querybuilder.feed.servlet'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('success', 'results',)
            header_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='info',
                    reason="AEM QueryBuilder Json Servlet detected",
                    path=path,
                )
                return True
        return False

