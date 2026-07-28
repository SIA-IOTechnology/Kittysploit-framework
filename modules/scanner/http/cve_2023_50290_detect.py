#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exposure of Sensitive Information to an Unauthorized Actor Vulnerability in Apache Solr."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Solr - Host Environment Variables Leak via Metrics API Detection',
        'description': 'Exposure of Sensitive Information to an Unauthorized Actor Vulnerability in Apache Solr. The Solr Metrics API publishes all unprotected environment variables available to each Apache Solr instance. Users can specify which environment variables to hide, however, the default list is designed to work for known secret Java system properties. Environment variables cannot be strictly defined in Solr, like Java system properties can be, and may be set for the entire host,unlike Java system properties which are set per-Java-proccess.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'apache', 'solr', 'exposure', 'vuln'],
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
            'https://solr.apache.org/security.html#cve-2023-50290-apache-solr-allows-read-access-to-host-environment-variables',
            'https://x.com/sirifu4k1/status/1746755165066236216?s=20',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-50290',
            'https://github.com/wy876/POC',
            'https://github.com/wy876/wiki',
        ],
        'cve': 'CVE-2023-50290',
    }

    def run(self):
        r = self.http_request(method="GET", path='/solr/admin/metrics', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"responseHeader":', '"solr.jetty":', 'system.env',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Apache Solr - Host Environment Variables Leak via Metrics API detected",
                path='/solr/admin/metrics',
            )
            return True
        return False

