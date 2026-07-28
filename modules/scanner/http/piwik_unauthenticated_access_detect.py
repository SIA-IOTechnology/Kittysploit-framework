#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Piwik/Matomo instances exposing analytics data without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Piwik/Matomo - Unauthenticated Access Detection',
        'description': 'Detected Piwik/Matomo instances exposing analytics data without authentication. When anonymous access was enabled, the API returned visitor statistics, page views, and other sensitive analytics data using the anonymous token.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'piwik', 'matomo', 'unauth', 'exposure', 'misconfig', 'analytics'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://developer.matomo.org/api-reference/reporting-api',
            'https://matomo.org/faq/general/faq_152/',
        ],
    }

    def run(self):
        for path in ('/index.php?module=API&method=VisitsSummary.get&idSite=1&period=day&date=today&format=json&token_auth=anonymous', '/matomo/index.php?module=API&method=VisitsSummary.get&idSite=1&period=day&date=today&format=json&token_auth=anonymous', '/piwik/index.php?module=API&method=VisitsSummary.get&idSite=1&period=day&date=today&format=json&token_auth=anonymous', '/index.php?module=API&method=SitesManager.getAllSites&format=json&token_auth=anonymous', '/matomo/index.php?module=API&method=SitesManager.getAllSites&format=json&token_auth=anonymous'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_any = ('nb_visits', 'nb_uniq_visitors', 'nb_actions', 'idsite', 'main_url',)
            ctype_any = ('application/json',)
            if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='high',
                    reason='Piwik/Matomo - Unauthenticated Access detected',
                    path=path,
                )
                return True
        return False

